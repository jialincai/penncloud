#include <arpa/inet.h>	// inet_pton
#include <climits>      // LONG_MAX, LONG_MIN
#include <csignal>      // signal
#include <cstddef>      // byte datatype
#include <cstring>      // strerror
#include <errno.h>      // errno
#include <fstream>		// ifstream
#include <netdb.h>      // addrinfo
#include <netinet/in.h> // AF_INET6
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> // socket
#include <sys/types.h>
#include <unistd.h> 	// getopt
#include <unordered_map>
#include <vector>
#include <set>

#include <sstream>
#include <iostream>		// cout
#include <string>       // to_string

#include "../library/socketcommunicator.h"
#include "../nlohmann/json.hpp"
#include "message.h"

using namespace std;
using json = nlohmann::json;

#define BACKLOG 10
#define BUFFSIZE 1000
#define MAXTHREADS 50

char portno[6] = {'1', '0', '0', '0', '0', '\0'};
bool print_dblog = false;

int listen_fd = -1;
int heartbeat_fd = -1;
int servIdx = -1;
bool isPrimary = false;

sockaddr_in masterAddrTCP;									// Address of backend master TCP socket.
sockaddr_in masterAddrDGRAM;								// Address of backend master DGRAM socket.
sockaddr_in thisNodeAddrTCP;								// Address of this nodes TCP socket address for sending data.
sockaddr_in thisNodeAddrDGRAM;								// Address of this nodes DGRAM socket address for heartbeats.
std::unordered_map<std::string, sockaddr_in> TCPAddrMap;	// A map of TCP socket addresses of to all other replication nodes in the network.
std::unordered_map<std::string, sockaddr_in> DGRAMAddrMap;	// A map of DGRAM socket addresses of to all other replication nodes in the network.

volatile bool shutting_down = false;

pthread_t thread_arr[MAXTHREADS];
volatile bool thread_avail[MAXTHREADS];
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

unordered_map<string, unordered_map<string, vector<char>>> bigTable;

unordered_map<string, vector<char>> preLoad;
vector<string> passwords = {"password", "password_100", "Enter%", "okay"};
vector<string> users = {"jialin", "yejin", "elaine", "radin"};

string ok_msg = "+OK Data updated \r\n";

enum State {INIT, PUT_READY, GET_READY, CPUT_READY, DEL_READY, AWAITING_V1, AWAITING_V2};

//--------------------------------------------------
// Dictionary (Ctrl + click to jump to functions of similar purpose)
//--------------------------------------------------
void get_cmd_opt(int argc, char *argv[]);						// Reading command line arguments and server setup.
void msg_client(const std::string line, const int client_fd);	// General purpose helper functions.
static void *thread_handle_client(void *arg);					// Functions related to signals and thread cleanup.
bool isMalformed(vector<string> cmdArgs, const int client_fd);	// Functions dealing with handling PUT/GET requests
int main(int argc, char *argv[]);

/**
 * This is a helper function that extracts the port number
 * and IP address from a line of the configuration file.
 */
void setAddr(std::string line, char *ip, char *portno)
{
	size_t position = line.find_first_of(':');
	if (position != line.npos) {
		std::string ipStr = line.substr(0, position);
		std::string portStr = line.substr(position + 1);
		if (ipStr.find_first_not_of("0123456789.") == ipStr.npos &&
				portStr.find_first_not_of("0123456789") == portStr.npos	) {
			strcpy(ip, ipStr.c_str());
			strcpy(portno, portStr.c_str());

			return;
		}
	}
	fprintf(stderr, "Unable to extract address and port number.\r\n");
	exit(EXIT_FAILURE);
}

/**
 * This function returns a IPv4 sockAddr with the IP address and
 * port number passed in.
 */
sockaddr_in setupSockAddr(char* ip, char* portno)
{
	sockaddr_in addr;
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(std::strtoul(portno, NULL, 10));
	inet_aton(ip, &addr.sin_addr);
	return addr;
}

/**
 * This function takes a null terminated IP address and portno
 * and turns it into unique key.
 */
std::string toKey(const char* ip, const char* portno) {
	return std::string(ip) + std::string(":") + std::string(portno);
}

/**
 * This function goes through each line of the configuration file
 * creates a sockaddr_in for each server in the network.
 */
void setupServAddrMap(char* configFile)
{
	/* Read each line of the configuration file. */
	char tcpPortno[6] = {};				// Server's bind port number.
	char tcpIP[16] = {};					// Server's bind IP address.
	char dgramPortno[6] = {};				// Server's bind port number.
	char dgramIP[16] = {};					// Server's bind IP address.

	std::ifstream in(configFile);
	std::string line = "";
	unsigned short lineCt = 0;
	while (in.peek() != EOF) {
		std::getline(in, line);
		//
		/* Parse the tcp and dgram socket address for each server. */
		size_t position = line.find_first_of(',');
		std::string tcpStr = line.substr(0, position);
		std::string dgramStr = line.substr(position + 1);
		setAddr(tcpStr, tcpIP, tcpPortno);
		setAddr(dgramStr, dgramIP, dgramPortno);

		//
		/* Setup address structure for the master node.
		   Setup the address structure for every replication node. */
		if (lineCt == 0) {
			masterAddrTCP = setupSockAddr(tcpIP, tcpPortno);
			masterAddrDGRAM = setupSockAddr(dgramIP, dgramPortno);
		} else if (lineCt == servIdx) {
			thisNodeAddrTCP = setupSockAddr(tcpIP, tcpPortno);
			thisNodeAddrDGRAM = setupSockAddr(dgramIP, dgramPortno);
		} else {
			sockaddr_in otherNodeAddrTCP = setupSockAddr(tcpIP, tcpPortno);
			sockaddr_in otherNodeAddrDGRAM = setupSockAddr(dgramIP, dgramPortno);
			TCPAddrMap.insert({toKey(tcpIP, tcpPortno), otherNodeAddrTCP});
			DGRAMAddrMap.insert({toKey(dgramIP, dgramPortno), otherNodeAddrDGRAM});
		}
		lineCt++;
	}
}

/* Parses command line arguments and sets the port number and print debug output flag.
 * Some rudimentary bad input checks performed which may lead to program termination. */
void get_cmd_opt(int argc, char *argv[]) {
	int opt;
	long checkPortno;
	while ((opt = getopt(argc, argv, "p:v")) != -1) {
		switch (opt) {
			case 'p':
				checkPortno = strtol(optarg, NULL, 10);
				if (checkPortno == 0 || checkPortno == LONG_MAX || checkPortno == LONG_MIN) {
					fprintf(stderr, "Invalid port number.\r\n");
					exit(EXIT_FAILURE);
				}
				strcpy(portno, optarg);
				break;
			case 'v':
				print_dblog = true;
				break;
			default:
				fprintf(stderr, "Invalid option.\r\n");
				exit(EXIT_FAILURE);
		}
	}

	// Extract configuration file and index of the current server instance.
	if (optind + 1 < argc) {
		servIdx = std::strtoul(argv[optind + 1], NULL, 10);
		setupServAddrMap(argv[optind]);
	} else {
		fprintf(stderr, "No server configuration file or server index provided.\r\n");
		exit(EXIT_FAILURE);
	}
}

/* Creates a server socket, binds it to a port, and listen for connections. */
void setup_server() {
	// Create a server-side socket.
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == -1) {
		fprintf(stderr, "Cannot create socket (%s).\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Free address and port immediately after program terminates.
	const int opt = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

	// Bind socket to port number.
	int bind_res = bind(listen_fd, (struct sockaddr*)&thisNodeAddrTCP, sizeof(thisNodeAddrTCP));
	if (bind_res == -1) {
		fprintf(stderr, "Cannot bind to port (%s).\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Start listening for connections.
	int listen_res = listen(listen_fd, BACKLOG);
	if (listen_res == -1) {
		fprintf(stderr, "listen error (%s).\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/**
 * This function creates a socket and binds them to the bind address and port number
 * specified in the configuration file.
 */
void setup_heartbeat_socket() {
	// Setup this node's datagram socket.
	heartbeat_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (heartbeat_fd == -1) {
		fprintf(stderr, "Cannot create socket (%s).\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	int bindRes = bind(heartbeat_fd, (struct sockaddr*)&thisNodeAddrDGRAM, sizeof(thisNodeAddrDGRAM));
	if (bindRes == -1) {
		fprintf(stderr, "Cannot bind to port (%s).\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	setsockopt(heartbeat_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

	const int opt = 1;
	setsockopt(heartbeat_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
}

/* Sends a message to the client via the specified file descriptor. */
void msg_client(const std::string line, const int client_fd) {
	char msg[line.length()];
	strcpy(msg, line.c_str());

	if (print_dblog) {
		fprintf(stderr, "[%d] N: %s", client_fd, msg);
	}

	int len = strlen(msg);
	int bytes_sent = send(client_fd, msg, len, 0);
	if (bytes_sent == -1) {
		fprintf(stderr, "Cannot send message to client (%s).\r\n", strerror(errno));
	}
}

void send_heartbeat_to_storageServers(sockaddr_in destAddr) {
	std::string msg(to_string(servIdx) + "\n");
	sendto(heartbeat_fd, msg.c_str(), msg.length(), 0, (struct sockaddr*)&destAddr, sizeof(destAddr));

//	if (print_dblog) {
//		fprintf(stderr, "Sending heartbeat %s", msg.c_str());
//	}
}

/**
 * This function sends a message to the master's datagram socket containing
 * the current primary servers IP and portno.
 */
void send_heartbeat_to_master() {
	std::string portno = std::to_string(ntohs(thisNodeAddrTCP.sin_port)).c_str();
	std::string msg(portno + "\n");
//	cout << portno << endl;
	sendto(heartbeat_fd, msg.c_str(), msg.length(), 0, (struct sockaddr*)&masterAddrDGRAM, sizeof(masterAddrDGRAM));

//	if (print_dblog) {
//		fprintf(stderr, "Is Primary -- Alerting master with message %s", msg.c_str());
//	}
}

/*
 * Used to connect to the server with the given addr.
 * Returns the file descriptor of the socket upon success or -1 if socket creation/connection failed.
 */
int connectToSocket(sockaddr_in socketAddr) {
	int socket_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		fprintf(stderr, "Thread cannot create replication socket (%s).\r\n", strerror(errno));
		return -1;
	}
	// Connect to storage server.
	int res = connect(socket_fd, (struct sockaddr*) &socketAddr, sizeof(socketAddr));
	if (res == -1) {
		return -1;
	}

	return socket_fd;
}

/* Fetches the value at specified row and column of Big Table.
 * If no matching keys an empty string is returned. */
string get_object(string row, string col) {
	if (bigTable.find(row) == bigTable.end()) {
		return "";
	}
	auto rowMap = bigTable.at(row);
	if (rowMap.find(col) == rowMap.end()) {
		return "";
	}

	vector<char> obj = rowMap[col];
	string byteString;
	for(auto const &c : obj) {
		byteString += c;
	}
	return byteString;
}

/* Splits a line into N tokens delimited by the first (N-1) white-spaces.
 * If less than N token can be generated, an empty vector is returned signaling error. */
vector<string> split(string line, int N) {
	vector<string> args;
	int string_pos = 0;
	int prev = 0;
	int count = 0;

	while (count < N - 1) {
		string_pos = line.find(' ', prev);

		// Invalid number of arguments.
		if (string_pos == line.npos) {
			return vector<string>();
		}

		string element = line.substr(prev, string_pos - prev);
		args.push_back(element);
		prev = string_pos + 1;
		count++;
	}

	// Invalid number of arguments.
	if (prev >= line.length()) {
		return vector<string>();
	}

	args.push_back(line.substr(prev));
	return args;
}

vector<char> bigTableToJSON() {
	json j = bigTable;
	std::stringstream buffer;
	buffer << j;
	std::string s = buffer.str();
	vector<char> toReturn(s.begin(), s.end());
	return toReturn;
}

std::

vector<char> bigTableToJSON_display() {
	std::stringstream buffer;

	buffer << "[";
	for (auto const &row_pair : bigTable) {
		for (auto const &col_pair : row_pair.second) {
			buffer << "{";
			buffer << std::string("\"row\":\"" + row_pair.first + "\",");
			buffer << std::string("\"col\":\"" + col_pair.first + "\",");
			std::string dataStr = "";
			for (auto const &c : col_pair.second) {
				dataStr += c;
			}

			buffer << std::string("\"value\":\"" + dataStr + "\"");

			buffer << "},";
		}
	}

	std::string s = buffer.str();
	s = s.substr(0, s.length() - 1);
	s += "]";
	vector<char> toReturn(s.begin(), s.end());
	return toReturn;
}

/* Cleans up memory and updates thread status when a thread is preparing to exit.
 * @param arg An array of arguments containing 0) Pointer to client file descriptor
 *                                             1) The thread_arr index of the thread to be cleaned up */
static void thread_cleanup(void *arg) {
	int *arg_caste = (int *)arg;
	int client_fd = arg_caste[0];	// Pointer to client file descriptor
	int i = arg_caste[1];			// The thread_arr index of the thread to be cleaned up

	if (shutting_down) {
		msg_client(string("-ERR Server shutting down.\r\n"), client_fd);
	}

	if (print_dblog) {
		fprintf(stderr, "[%d] Connection closed\r\n", client_fd);
	}

	close(client_fd);
	delete arg_caste;

	pthread_mutex_lock(&mutex);
	thread_avail[i] = true;
	pthread_mutex_unlock(&mutex);
}

/* Handles SIGINT. Sets shutting down flag to true and signals
 * for all threads to call thread_cleanup and terminate. */
void sigint_handler(int signum) {
	shutting_down = true;
	for (int i = 0; i < MAXTHREADS; i++) {
		if (!thread_avail[i]) {
			pthread_cancel(thread_arr[i]);
			pthread_join(thread_arr[i], NULL);
		}
	}
	return;
}

bool isMalformed(vector<string> cmdArgs, const int client_fd) {
	if (cmdArgs.size() == 0) {
		msg_client(string("-ERR malformed command.\r\n"), client_fd);
		return true;
	}
	return false;
}

void reset(Message &m, State &s) {
	s = INIT;
	m.clear();
}

/* This function will extract arguments from command to populate a message object.
 * Then kick the program into the appropriate command state. */
void populate_message(const string command, Message &msg, State &s, const int client_fd) {
	vector<string> cmdArgs;

	// No command from client.
	if (command == "") {
		return;
	}

	string CMD = command.substr(0, command.find(' '));
	if (CMD == "PUT") {
		cmdArgs = split(command, 4);
		if (!isMalformed(cmdArgs, client_fd)) {
			msg.type = PUT;
			msg.row = cmdArgs[1];
			msg.col = cmdArgs[2];
			msg.v1BytesToRead = strtoull(cmdArgs[3].c_str(), NULL, 10);
			if (msg.v1BytesToRead == 0) {
				return;
			}
			s = AWAITING_V1;
		}
	} else if (CMD == "GET") {
		cmdArgs = split(command, 3);
		if (!isMalformed(cmdArgs, client_fd)) {
			msg.type = GET;
			msg.row = cmdArgs[1];
			msg.col = cmdArgs[2];
			s = GET_READY;
		}
	} else if (CMD == "CPUT") {
		cmdArgs = split(command, 5);
		if (!isMalformed(cmdArgs, client_fd)) {
			msg.type = CPUT;
			msg.row = cmdArgs[1];
			msg.col = cmdArgs[2];
			msg.v1BytesToRead = strtoull(cmdArgs[3].c_str(), NULL, 10);
			msg.v2BytesToRead = strtoull(cmdArgs[4].c_str(), NULL, 10);
			if (msg.v1BytesToRead == 0 || msg.v1BytesToRead == 0) {
				return;
			}
			s = AWAITING_V1;
		}
	} else if (CMD == "DEL") {
		cmdArgs = split(command, 3);
		if (!isMalformed(cmdArgs, client_fd)) {
			msg.type = DEL;
			msg.row = cmdArgs[1];
			msg.col = cmdArgs[2];
			s = DEL_READY;
		}
	} else {
		msg_client(string("-ERR Invalid command.\r\n"), client_fd);
		reset(msg, s);
	}
}

void handle_get(Message &msg, State &s, int client_fd) {
	// Row not found
	if (bigTable.find(msg.row) == bigTable.end()) {
		msg_client(string("-ERR Row not found.\r\n"), client_fd);
		reset(msg, s);
		return;
	}

	auto rowMap = bigTable[msg.row];

	// Column not found
	if (rowMap.find(msg.col) == rowMap.end()) {
		msg_client(string("-ERR Column not found.\r\n"), client_fd);
		reset(msg, s);
		return;
	}

	// If front end calls GET bigtable json.
	// We return the bigTable as a JSON file.
	vector<char> obj;
	if (msg.row == "bigtable" && msg.col == "json") {
		obj = bigTableToJSON();
	} else if (msg.row == "bigtable" && msg.col == "json-admin") {
		obj = bigTableToJSON_display();
	} else {
		obj = rowMap[msg.col];
	}

	// Send object to client.
	unsigned long long byteCount = 0;
	string byteString = "";
	for(auto const &c : obj) {
		byteString += c;
		byteCount++;
	}

	string toSend = string("+OK ") + to_string(byteCount) + string("\r\n");
	msg_client(toSend, client_fd);
	msg_client(byteString, client_fd);

	reset(msg, s);
}

void handle_del(Message &msg, State &s, int client_fd) {
	if (bigTable.find(msg.row) == bigTable.end()) {
		msg_client(string("-ERR No value to delete.\r\n"), client_fd);
		reset(msg, s);
		return;
	}

	int elemsDeleted = bigTable[msg.row].erase(msg.col);
	if (elemsDeleted == 0) {
		msg_client(string("-ERR No value to delete.\r\n"), client_fd);
		reset(msg, s);
		return;
	}

	if (isPrimary) {
		// Send message to all other replication servers to delete
		for (auto const &pair : TCPAddrMap) {
			// Create a socket, try to connect and send message.
			// If connection fails, try the next one.
			int fd = connectToSocket(pair.second);
			if (fd != -1) {
				SocketCommunicator sc(fd);
				sc.send_DEL_request(msg.row, msg.col);
			}
			close(fd);
		}
	}

	msg_client(string("+OK Object deleted.\r\n"), client_fd);
	reset(msg, s);
}

void handle_put(Message &msg, State &s, int client_fd) {
	vector<char> data(msg.v1.begin(), msg.v1.end());

	if (bigTable.find(msg.row) == bigTable.end()) {
		unordered_map<string, vector<char> > newRow;
		newRow[msg.col] = data;
		bigTable[msg.row] = newRow;
	} else {
		if (msg.row == "users") {
			std::string msgs("From <jialin@localhost> Wed Dec 14 07:02:10 2022\r\nSubject: Welcome\r\nFirst message.\r\n.\r\n");
			std::vector<char> defaultMbox(msgs.begin(), msgs.end());
			bigTable[std::string(msg.col + "-mail")]["mbox"] = defaultMbox;
			bigTable[std::string(msg.col + "-storage")]["config"] = vector<char>();
		}
		bigTable[msg.row][msg.col] = data;
	}

	// Send message to all other replication servers to delete
	if (isPrimary) {
		for (auto const &pair : TCPAddrMap) {
			// Create a socket, try to connect and send message.
			// If connection fails, try the next one.
			int fd = connectToSocket(pair.second);
			if (fd != -1) {
				SocketCommunicator sc(fd);
				sc.send_PUT_request(msg.row, msg.col, data);
			}
			close(fd);
		}
	}

	msg_client(string("+OK Value stored.\r\n"), client_fd);
	reset(msg, s);
}

void handle_cput(Message &msg, State &s, int client_fd) {
	string storedObj = get_object(msg.row, msg.col);

	// Object not found
	if (storedObj.size() < 1) {
		msg_client(string("-ERR No value to compare.\r\n"), client_fd);
		reset(msg, s);
		return;
	}

	if (storedObj == msg.v1) {
		vector<char> data(msg.v2.begin(), msg.v2.end());
		bigTable[msg.row][msg.col] = data;
		msg_client(string("+OK Value stored.\r\n"), client_fd);
	} else {
		msg_client(string("+OK Condition not satisfied.\r\n"), client_fd);
	}

	reset(msg, s);
}

/* Given the current state and the message contents call a PUT/GET/CPUT/DEL handler. */
void handle_message(State &s, Message &msg, const int client_fd) {
	if (s == GET_READY) {
		handle_get(msg, s, client_fd);
	} else if (s == DEL_READY) {
		handle_del(msg, s, client_fd);
	} else if (s == PUT_READY) {
		handle_put(msg, s, client_fd);
	} else if (s == CPUT_READY) {
		handle_cput(msg, s, client_fd);
	// If currently awaiting values or in NONE state, then there's nothing to handle yet.
	} else {
		return;
	}
}

/**
 * Continuously check for incoming messages at a client socket and handles commands.
 * This function closes the socket file descriptor when the client instructs to close the connection.
 * @param arg An array of arguments containing 0) Pointer to client file descriptor
 *                                             1) The thread_arr index of the thread to be cleaned up */
static void *thread_handle_client(void *arg) {
	pthread_cleanup_push(thread_cleanup, arg);

	int *arg_caste = (int *)arg;
	int client_fd = arg_caste[0];	// Pointer to client file descriptor
	int i = arg_caste[1];			// The thread_arr index of the thread to be cleaned up

	std::string chunk;			// Contents received up to <CRLF> sequence.
	State state = INIT;			// The current program state.
	Message msg = Message();	// A message object that will store command arguments.
	char char_buf[BUFFSIZE];	// Buffer to be populate by recv call.

	bool connection_open = true;
	while (connection_open) {
		int bytes_read = recv(client_fd, &char_buf[0], BUFFSIZE, 0);

		// Client closed connection.
		if (bytes_read == 0 || bytes_read == -1) {
			fprintf(stderr, "Client closed connection.\r\n");
			connection_open = false;
		}
		// Handle data in received.
		else {
			std::string tmp(char_buf);	// Convert char_buf contents into a string for easy manipulation.
			int prev_linefeed_pos = 0;
			for (int i = 0; i < bytes_read; i++) {
				// Currently in NONE state AND <CRLF> encountered
				if (state == INIT && i > 0 && char_buf[i - 1] == '\r' && char_buf[i] == '\n') {
					std::string to_linefeed = tmp.substr(prev_linefeed_pos, i - prev_linefeed_pos + 1);
					chunk += to_linefeed;

					if (print_dblog) {
						fprintf(stderr, "[%d] C: %s", client_fd, chunk.c_str());
					}

					chunk = chunk.substr(0, chunk.size() - 2);		// Remove <CRLF> at end of chunk
					populate_message(chunk, msg, state, client_fd);
					handle_message(state, msg, client_fd);

					// Prepare to read next chunk.
					chunk = std::string();
					prev_linefeed_pos = i + 1;
				// Current in AWAITING_V1 state so next N bytes should be treated as value to be stored.
				} else if (state == AWAITING_V1) {
					msg.v1 += tmp[i];
					prev_linefeed_pos++;
					if (--msg.v1BytesToRead == 0) {
						if (msg.type == PUT) {
							state = PUT_READY;
							handle_message(state, msg, client_fd);
						} else if (msg.type == CPUT) {
							state = AWAITING_V2;
						}
					}
				// Current in AWAITING_V2 state so next N bytes should be treated as value to be stored.
				} else if (state == AWAITING_V2) {
					msg.v2 += tmp[i];
					prev_linefeed_pos++;
					if (--msg.v2BytesToRead == 0) {
						state = CPUT_READY;
						handle_message(state, msg, client_fd);
					}
				}
			}
			// No <CRLF> encountered in the data received. We must received more data to complete the command.
			if (state == INIT && prev_linefeed_pos < bytes_read) {
				chunk += tmp.substr(prev_linefeed_pos, bytes_read - prev_linefeed_pos);
			}
		}
	}

	pthread_cleanup_pop(1);
	pthread_exit(NULL);
}

/**
 * Create datagram sockets for handling heartbeat. And deciding which thread is the current primary. */
static void *thread_handle_primary(void *arg) {
	setup_heartbeat_socket();
	sleep(1);	// Give server time to recieve initial heartbeat from other servers.

	// Continuously send heartbeats and determine which server should be the primary.
	while (!shutting_down) {
		// Send a heartbeat containing this server's ID to all other replication servers.
		for (auto const &pair : DGRAMAddrMap) {
			sockaddr_in otherAddr = pair.second;
			send_heartbeat_to_storageServers(otherAddr);
		}

		// Check for ID received from other live replication servers.
		// If this server has the largest ID, set isPrimary flag to true
		// and start sending heartbeat containng TCP address and port to master.
		sockaddr_in srcAddr;
		socklen_t srcSize = sizeof(srcAddr);
		char inBuf[BUFFSIZE];

		int min_ID = INT_MAX;

		int rlen = -1;
		while (true) {
			int rlen = recvfrom(heartbeat_fd, inBuf, sizeof(inBuf), 0, (struct sockaddr*)&srcAddr, &srcSize);
			if (rlen == 0 || rlen == -1) {
				break;
			}

			inBuf[rlen] = 0;
//			if (print_dblog && rlen != 0 && rlen != -1) {
//				fprintf(stderr, "Received heartbeat %s", std::string(inBuf).c_str());
//			}

			int otherID = strtoull(inBuf, NULL, 10);
			if (otherID < min_ID) {
				min_ID = otherID;
			}

		}

		if (min_ID > servIdx) {
			isPrimary = true;
			send_heartbeat_to_master();
//			fprintf(stderr, "IS PRIMARY\n");
		} else {
			isPrimary = false;
		}

		sleep(1);
	}

	pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
	// Setting up signals, threads, and sockets
	struct sigaction new_action;
	new_action.sa_handler = sigint_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 1;
	sigaction(SIGINT, &new_action, NULL);

	for (auto &status : thread_avail) {
		status = true;
	}
	get_cmd_opt(argc, argv);
	setup_server();

	pthread_t heartbeat_thread;
	pthread_create(&heartbeat_thread, NULL, thread_handle_primary, nullptr);

//---------------
// START PRELOAD
//---------------
	// Preload users.
	for (int i = 0; i < users.size(); i++) {
		vector<char> data(passwords[i].begin(), passwords[i].end());
		preLoad[users[i]] = data;
	}
	bigTable["users"] = preLoad;

	// Preload mailboxes
	unordered_map<string, vector<char>> newRow1;
	std::string msgs("From <temp@localhost> Wed Dec 14 07:02:10 2022\r\nSubject: Welcome\r\nThis is message 1\r\n.\r\nFrom <temp@localhost> Wed Dec 15 12:02:10 2022\r\nSubject: dummy\r\nThis is message 2\r\n.\r\n");
	vector<char> dummyMbox(msgs.begin(), msgs.end());
	newRow1["mbox"] = dummyMbox;
	bigTable["jialin-mail"] = newRow1;
	bigTable["yejin-mail"] = newRow1;
	bigTable["elaine-mail"] = newRow1;
	bigTable["radin-mail"] = newRow1;

	// Preload storage drive
	unordered_map<string, vector<char>> newRow2;
	std::string config("/,X\r\n/lectures,X\r\n/lectures/notes,ABC\r\n/file1,BCD\r\n/file2,CDE");
	vector<char> dummyConfig(config.begin(), config.end());
	newRow2["config"] = dummyConfig;
	bigTable["jialin-storage"] = newRow2;
	bigTable["yejin-storage"] = newRow2;
	bigTable["elaine-storage"] = newRow2;
	bigTable["radin-storage"] = newRow2;

	vector<char> obj = {'a', 'b', 'c'};

	for (auto const &pair : bigTable["users"]) {
		std::string name = pair.first;
		bigTable[std::string(name + "-storage")]["ABC"] = obj;
		bigTable[std::string(name + "-storage")]["BCD"] = obj;
		bigTable[std::string(name + "-storage")]["CDE"] = obj;
	}

	bigTable["bigtable"]["json"] = vector<char>();
	bigTable["bigtable"]["json-admin"] = vector<char>();
//---------------
// DONE PRELOAD
//---------------
	// Ask any other active backend server for their bigtable
	for (auto const &pair : TCPAddrMap) {
		// Create a socket, try to connect and send message.
		// If connection fails, try the next one.
		int fd = connectToSocket(pair.second);
		if (fd != -1) {
			SocketCommunicator sc(fd);
			sc.send_GET_request("bigtable", "json");
			bool success = false;
			vector<char> res = sc.parse_GET_response(success);
			string jsonStr = "";
			for (auto c : res) {
				jsonStr += c;
			}
			json jsonObj = json::parse(jsonStr);
			unordered_map<string, unordered_map<string, vector<char>>> backup = jsonObj;
			bigTable = backup;
		}
		close(fd);
	}


	while (!shutting_down) {
		struct sockaddr_storage client_addr;
		socklen_t client_addr_size = sizeof(client_addr);

		int *client_fd = new int[2];
		client_fd[0] = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_size);

		if (client_fd[0] == -1 || shutting_down) {
			delete[] client_fd;
			break;
		}

		if (print_dblog) {
			fprintf(stderr, "[%d] New connection\r\n", *client_fd);
		}

		for (int i = 0; i < MAXTHREADS; i++) {
			if (thread_avail[i] == true) {
				client_fd[1] = i;
				pthread_create(&thread_arr[i], NULL, thread_handle_client, client_fd);
				pthread_mutex_lock(&mutex);
				thread_avail[i] = false;
				pthread_mutex_unlock(&mutex);
				break;
			}
		}
	}

	exit(EXIT_SUCCESS);
}
