#include "socketcommunicator.h"

SocketCommunicator::SocketCommunicator(int socket_fd) : socket_fd(socket_fd)
{}

// helper function which sends the given message to the socket id
bool SocketCommunicator::send_wrapper(const char* msg) {
	int len = strlen(msg);
	int bytes_sent = send(socket_fd, msg, len, 0);
	if (bytes_sent == -1) {
		fprintf(stderr, "Cannot send message to client (%s).\r\n", strerror(errno));
		return false;
	}
	return true;
}

// sending a get message
bool SocketCommunicator::send_GET_request(const std::string row, const std::string col) {
	std::string msg = std::string("GET " + row + " " + col + "\r\n");
	return send_wrapper(msg.c_str());
}


// parsing the get message
std::vector<char> SocketCommunicator::parse_GET_response(bool &success) {
	// Read how many bytes the response is
	unsigned int bytesToRead = -1;

	char char_buf[BUFFSIZE];
	std::string response_header;
	std::vector<char> byte_array;		// Value in BigTable
	std::vector<char> empty;
	bool inReadingMboxState = false;

	while (bytesToRead != 0) {

		// keep on reading the message sent from the backend
		int bytes_read = recv(socket_fd, &char_buf[0], BUFFSIZE, 0);

		if (bytes_read == 0) {
			success = false;
			return empty;
		}

		// we add the bytes received to a vector of chars
		for (int i = 0; i < bytes_read; i++) {
			if (inReadingMboxState && bytesToRead != 0) {
				if (bytesToRead != 0) {
					byte_array.push_back(char_buf[i]);
					bytesToRead--;
				} else {
					break;
				}
			}

			// once we are at the end of buffer, we send ok message to caller
			if (!inReadingMboxState && i != 0 && char_buf[i] == '\n' && char_buf[i-1] == '\r') {
				response_header += std::string(char_buf, i + 1);
				if (response_header.find("+OK ") == 0) {
					inReadingMboxState = true;
					std::string arg = response_header.substr(strlen("+OK "), response_header.size() - strlen("+OK \r\n"));
					bytesToRead = strtoul(arg.c_str(), NULL, 10);
				} else {
					success = false;
					return empty;
				}

				// if we are at the end of buffer and still no \r\n we add to response and continue reading
			} else if (!inReadingMboxState && i == bytes_read - 1) {
				response_header += std::string(char_buf);
			}
		}
	}

	// return the vector of chars retrived
	success = true;
	return byte_array;
}

bool SocketCommunicator::send_PUT_request(const std::string row, const std::string col, std::vector<char> byte_array) {

	// construct PUT message which will be sent to backend server
	std::string msg = std::string("PUT " + row + " " + col + " " + std::to_string(byte_array.size()) + "\r\n");
	send_wrapper(msg.c_str());
	return send_wrapper(std::string(byte_array.begin(), byte_array.end()).c_str());
}

bool SocketCommunicator::parse_PUT_response() {
	char char_buf[BUFFSIZE];
	std::string response;


	while (true) {

		// read response sent by backend server
		int bytes_read = recv(socket_fd, &char_buf[0], BUFFSIZE, 0);

		if (bytes_read == 0) {
			return false;
		}

		// go through buffer and check if we received error message or not and return appropiate response
		for (int i = 0; i < bytes_read; i++) {
			if (i != 0 && char_buf[i] == '\n' && char_buf[i-1] == '\r') {
				response += std::string(char_buf, i + 1);
				if (response.find("-ERR ") == 0) {
					return false;
				} else {
					return true;
				}
			} else if (i == bytes_read - 1) {
				response += std::string(char_buf);
			}
		}
	}
}


bool SocketCommunicator::send_DEL_request(std::string row, std::string col) {

	// construct and send response
	std::string msg = std::string("DEL " + row + " " + col + "\r\n");
	return send_wrapper(msg.c_str());
}

bool SocketCommunicator::parse_DEL_response() {
	char char_buf[BUFFSIZE];
	std::string response;


	// parse response and send back to frontend server
	while (true) {
		int bytes_read = recv(socket_fd, &char_buf[0], BUFFSIZE, 0);

		if (bytes_read == 0) {
			return false;
		}

		for (int i = 0; i < bytes_read; i++) {
			if (i != 0 && char_buf[i] == '\n' && char_buf[i-1] == '\r') {
				response += std::string(char_buf, i + 1);
				if (response.find("-ERR ") == 0) {
					return false;
				} else {
					return true;
				}
			} else if (i == bytes_read - 1) {
				response += std::string(char_buf);
			}
		}
	}
}

// function to convert map to configuration file to then store in bigTable
bool SocketCommunicator::mapToConfig(std::unordered_map<std::string, std::string> map, std::string username) {

	// go through map, convert to csv file formate (key,value), then store in bigtable
	std::vector<char> result;
	for (auto const &pair : map) {
		std::string key = pair.first;
		std::string value = pair.second;

		for (auto const &c : key) {
			result.push_back(c);
		}
		result.push_back(',');

		for (auto const &c : value) {
			result.push_back(c);
		}
		result.push_back('\r');
		result.push_back('\n');
	}

	send_PUT_request(std::string(username + "-storage"), "config", result);
	return parse_PUT_response();
}

// function to convert configfile to map
std::unordered_map<std::string, std::string> SocketCommunicator::configToMap(std::string username, bool &success) {

	std::unordered_map<std::string, std::string> toReturn;

	if (!send_GET_request(std::string(username + "-storage"), "config")) {
		fprintf(stderr, "Error getting config file\r\n");
		success = false;
		return toReturn;
	}

	std::vector<char> configFile = parse_GET_response(success);

	if (!success) {
		fprintf(stderr, "Error parsing GET response\r\n");
		return toReturn;
	}

	// go through vector char and create map keys and values based on comma.
	std::string path;
	std::string code;
	bool key = true;

	for (int i = 0; i < configFile.size(); i++) {
		if (configFile[i] == ',') {
			key = !key;
		}
		else if (configFile[i] == '\r') continue;

		else if (configFile[i] == '\n') {
			toReturn[path] = code;
			key = true;
			code.clear();
			path.clear();
		} else if (i == configFile.size() - 1) {
			code += configFile[i];
			toReturn[path] = code;
		} else {
			if (key) {
				path += configFile[i];
			} else {
				code += configFile[i];
			}
		}
	}

	// return map
	return toReturn;
}

// function to rename file
bool SocketCommunicator::rename_file(std::string path, std::string new_name,
		std::unordered_map<std::string, std::string>& map, std::string username) {


	auto tempMap = map;

	// find current hash of file
	std::string hash = map[path];

	if (hash.size() < 1) {
		fprintf(stderr, "Path does not exist\r\n");
		return false;
	}

	map.erase(path);
	int last_slash = path.rfind('/');

	if (last_slash == std::string::npos) {
		fprintf(stderr, "Invalid path\r\n");
		return false;
	}

	// take path of file and only change file name
	std::string new_path = path.substr(0, last_slash);
	new_path += '/';
	new_path += new_name;

	// make the new path equal to previous hash
	map[new_path] = hash;

	// update hashtable
	bool success = mapToConfig(map, username);
	if (!success) {
		map = tempMap;
		return false;
	}

	return true;
}

// function to move file
bool SocketCommunicator::move_file(std::string file_path, std::string new_path,
		std::unordered_map<std::string, std::string>& map, std::string username) {

	auto tempMap = map;

	// get current hash
	std::string hash = map[file_path];

	if (hash.size() < 1) {
		fprintf(stderr, "Path does not exist or invalid\r\n");
		return false;
	}

	int last_slash = file_path.rfind('/');
	std::string file = file_path.substr(last_slash + 1);
	new_path += file;

	// erase previous path and update with new one
	map.erase(file_path);
	map[new_path] = hash;

	// create new config file with new map
	bool success = mapToConfig(map, username);
	if (!success) {
		map = tempMap;
		return false;
	}

	return true;
}

// function to move folder
bool SocketCommunicator::move_folder(std::string old_path, std::string new_path,
		std::unordered_map<std::string, std::string>& map, std::string username) {

	auto tempMap = map;
	std::vector<std::vector<std::string>> make_fix;

	for (auto& pair : map) {

		// go through entire map and check to see if file path matches
		if (is_part(old_path, pair.first)) {

			// if so, update the file path to equal the new path
			std::string to_change = pair.first.substr(old_path.size());
			std::string to_put = new_path + to_change;

			std::vector<std::string> to_add;

			// store all changes
			to_add.push_back(pair.first);
			to_add.push_back(to_put);
			to_add.push_back(pair.second);

			make_fix.push_back(to_add);

		}

	}

	// go through changes and update them in map
	for (auto& str_arr : make_fix) {
		map.erase(str_arr[0]);
		map[str_arr[1]] = str_arr[2];
	}

	bool success = mapToConfig(map, username);
	if (!success) {
		map = tempMap;
		return false;
	}

	return true;
}

// function to rename folder
bool SocketCommunicator::rename_folder(std::string old_path, std::string new_name,
		std::unordered_map<std::string, std::string>& map, std::string username) {


	auto tempMap = map;


	if (old_path.find('.') != std::string::npos) {
		fprintf(stderr, "Invalid period in file paths\r\n");
		return false;
	}
	else if (old_path.rfind('/') == std::string::npos) {
		fprintf(stderr, "Invalid old path entered\r\n");
		return false;
	}

	std::vector<std::vector<std::string>> to_change;
	int last_slash = old_path.rfind('/');

	for (auto& pair : map) {

		// go through every pair and check that paths match up
		if (is_part(old_path, pair.first)) {

			// if they do, we update the path with new folder name
			std::string curr_path = pair.first;
			curr_path.replace(last_slash + 1, new_name.size(), new_name);
			std::vector<std::string> to_add;

			to_add.push_back(pair.first);
			to_add.push_back(curr_path);
			to_add.push_back(pair.second);

			to_change.push_back(to_add);

		}

	}

	for (auto& str_arr : to_change) {

		// go through map and update all the needed changes
		map.erase(str_arr[0]);
		map[str_arr[1]] = str_arr[2];

	}

	// update config file with new map
	bool success = mapToConfig(map, username);
	if (!success) {
		map = tempMap;
		return false;
	}

	return true;
}

// function to check if two paths are the same or not
bool is_part(std::string folder_path, std::string file_path) {
	if (folder_path.size() > file_path.size()) return false;

	for (int i = 0; i < folder_path.size(); i++) {
		if (folder_path[i] != file_path[i]) return false;
	}

	return true;

}


bool SocketCommunicator::uploadFile(std::unordered_map<std::string, std::string> &fileMap, std::string username,
									std::string filePath, std::vector<char> file) {
	// Store object
	bool success = send_PUT_request(std::string(username + "-storage"), generate_hash(filePath), file);
	if (!success) {
		return false;
	}

	success = parse_PUT_response();
	if (!success) {
		return false;
	}

	// Update local map
	fileMap[filePath] = generate_hash(filePath);

	// Update remote configuration file
	success = mapToConfig(fileMap, username);
	if (!success) {
		// Failed! Roll back changes.
		fileMap.erase(filePath);
		return false;
	}
	return true;
}

/**
 * Download a file from the bigTable. Upon successful download set success to true
 * and return the file as a byte array.
 */
std::vector<char> SocketCommunicator::downloadFile(std::string username, std::string fileHash, bool &success) {
	std::vector<char> obj;

	success = send_GET_request(std::string(username + "-storage"), fileHash);
	if (!success) {
		return obj;
	}

	obj = parse_GET_response(success);
	if (!success) {
		return obj;
	}

	return obj;
}

bool SocketCommunicator::deleteFile(std::unordered_map<std::string, std::string> &fileMap,
									std::string username, std::string filePath) {
	// Update local file map
	std::string hashCopy = fileMap[filePath];
	fileMap.erase(filePath);

	// Update remote configuration file
	bool success = mapToConfig(fileMap, username);
	if (!success) {
		// Failed! Restore changes.
		fileMap[filePath] = hashCopy;
		return false;
	}

	// Send DEL request
	success = send_DEL_request(std::string(username + "-storage"), hashCopy);
	// We don't really care if the DEL request fails because the file will be inaccessible.

	return true;
}

/**
 * Create folder in bigTable
 */
bool SocketCommunicator::createFolder(std::unordered_map<std::string, std::string> &fileMap,
				  	  	  	  	  	  std::string folderPath, std::string username) {
	// Update local file map
	fileMap[folderPath] = "X";

	// Update remote configuration file
	bool success = mapToConfig(fileMap, username);
	if (!success) {
		// Failed! Roll back changes.
		fileMap.erase(folderPath);
		return false;
	}

	return true;
}

/**
 * Delete folder in bigTable
 */
bool SocketCommunicator::deleteFolder(std::unordered_map<std::string, std::string> &fileMap,
				  	  	  	  	  	  std::string folderPath, std::string username) {
	// Create a set including folderPath and all nested paths
	std::unordered_map<std::string, std::string> toDelete;
	for (auto const &pair : fileMap) {
		if (pair.first.find(folderPath) == 0) {
			toDelete[pair.first] = pair.second;
		}
	}

	// Update local file map
	for (auto const &pair : toDelete) {
		fileMap.erase(pair.first);
	}

	// Update remote configuration file
	bool success = mapToConfig(fileMap, username);
	if (!success) {
		// Failed! Roll back changes.
		for (auto const &pair : toDelete) {
			fileMap[pair.first] = pair.second;
		}
		return false;
	}

	// Delete files from bigTable
	for (auto const &pair : toDelete) {
		fileMap.erase(pair.first);
	}
	// We don't care if delete fails because the files will be inaccessible.

	return true;
}

void computeDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer)
{
  /* The digest will be written to digestBuffer, which must be at least MD5_DIGEST_LENGTH bytes long */
  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, data, dataLengthBytes);
  MD5_Final(digestBuffer, &c);
}

// Generates a unique hash string from a string.
std::string generate_hash(std::string line) {
	char* data = new char[line.length() + 1];
	line.copy(data, line.length());

	unsigned char digestBuffer[MD5_DIGEST_LENGTH];
	computeDigest(data, line.length(), digestBuffer);

	std::string result;
	for (size_t i = 0 ; i < 17 ; i++) {
		result += "0123456789ABCDEF"[digestBuffer[i] / 16];
		result += "0123456789ABCDEF"[digestBuffer[i] % 16];
	}

	delete[] data;
	return result;
}

