#ifndef LIBRARY_SOCKETCOMMUNICATOR_H_
#define LIBRARY_SOCKETCOMMUNICATOR_H_

#include <cstring>		// strerror
#include <sys/socket.h>
#include <openssl/md5.h>// for hashing
#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <iostream>


#define BUFFSIZE 1000

class SocketCommunicator {
private:
	int socket_fd;	// The socket that this communicator will use send and receive messages from.

public:
	SocketCommunicator(int socket_fd);

	/**
	 * Given an unordered_map, convert it into a CSV file and send a PUT request to the bigTable.
	 */
	bool mapToConfig(const std::unordered_map<std::string, std::string> map, std::string username);

	/**
	 * Given a user, GET the data from the BigTable and convert to unordered_map
	 */
	std::unordered_map<std::string, std::string> configToMap(std::string username, bool &success);

	/**
	 * Uploads a file to bigTable.
	 */
	bool uploadFile(std::unordered_map<std::string, std::string> &fileMap, std::string username,
					std::string filePath, std::vector<char> file);

	/**
	 * Download a file from the bigTable. Upon successful download set success to true
	 * and return the file as a byte array.
	 */
	std::vector<char> downloadFile(std::string username, std::string fileHash, bool &success);

	/**
	 * Delete a file from bigTable
	 */
	bool deleteFile(std::unordered_map<std::string, std::string> &fileMap, std::string username, std::string filePath);

	/**
	 * Create folder in bigTable
	 */
	bool createFolder(std::unordered_map<std::string, std::string> &fileMap,
					  std::string folderPath, std::string username);

	/**
	 * Delete folder in bigTable
	 */
	bool deleteFolder(std::unordered_map<std::string, std::string> &fileMap,
					  std::string folderPath, std::string username);

	/**
	 * A function that sends the specified message through socket provided.
	 * Returns false if the message could not be sent, otherwise true.
	 */
	bool send_wrapper(const char* msg);

	/**
	 * This function sends a GET request to the backend server.
	 * Returns false if the message could not be sent, otherwise true.
	 */
	bool send_GET_request(const std::string row, const std::string col);

	/**
	 * This function parses a GET response from the backend server.
	 * Returns stored value as a vector of bytes and updates &success if +OK response received.
	 */
	std::vector<char> parse_GET_response(bool &success);

	/**
	 * This function sends a PUT request to the backend server.
	 * Returns false if the message could not be sent, otherwise true.
	 */
	bool send_PUT_request(const std::string row, const std::string col, std::vector<char> byte_array);

	/**
	 * This function parses a PUT response from the backend server.
	 * If the PUT response contains -ERR return false.
	 */
	bool parse_PUT_response();

	/**
	 * This function renames a file. The first argument is the full path of the file, second is the new name on its own.
	 * Returns true if successful, false otherwise
	 *
	 * rename_file("root/radin-storage/cis 5050/unit1/test1.txt", "testOne.txt", mapObject)
	 *
	 */
	bool rename_file(std::string path, std::string new_name, std::unordered_map<std::string, std::string>& map, std::string username);

	/**
	 * This function moves a file. The first argumemnt is the full path of the file to move, second is the full path of the new folder.
	 * Return true if successful, false otherwise.
	 *
	 * move_file("root/radin-storage/cis 5050/unit1/test1.txt", "root/radin-storage", mapObject)
	 *
	 */
	bool move_file(std::string file_path, std::string new_path, std::unordered_map<std::string, std::string>& map, std::string username);

	/**
	 * This function moves a folder. The first argument is the full path of the folder, second is the folder that this one will move INTO.
	 * Returns true if successful, false otherwise.
	 *
	 * move_folder("root/radin-storage/cis 5050/unit1", "root/radin-storage", mapObject)
	 *
	 */
	bool move_folder(std::string old_path, std::string new_path, std::unordered_map<std::string, std::string>& map, std::string username);

	/**
	 * This function renames a folder. The first argument is the location of the folder to move. The second arg is the new name only.
	 * Returns true if successful, false otherwise.
	 *
	 * rename_folder("root/radin-storage/cis 5050/unit1", "unitOne", mapObject)
	 *
	 */

	bool rename_folder(std::string old_path, std::string new_path, std::unordered_map<std::string, std::string>& map, std::string username);

	/**
	 * Sends a DEL request to the bigTable. Returns false if the message could not be send. Otherwise true.
	 */
	bool send_DEL_request(std::string row, std::string col);

	/**
	 * This function parses a DEL response from the backend server.
	 * If the DEL response contains -ERR return false.
	 */
	bool parse_DEL_response();
};

// Generates a unique hash string from a string.
void computeDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer);
std::string generate_hash(std::string line);
bool is_part(std::string folder_path, std::string file_path);

#endif /* LIBRARY_SOCKETCOMMUNICATOR_H_ */
