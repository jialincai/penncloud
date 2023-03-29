#include <arpa/inet.h>	// inet_pton
#include <climits>		// LONG_MAX, LONG_MIN
#include <csignal>		// signal
#include <ctime>		// time_t
#include <errno.h>		// errno
#include <fstream>		// ifstream
#include <netdb.h>		// addrinfo
#include <netinet/in.h>	// AF_INET6
#include <openssl/md5.h>// for hashing
#include <sstream>		// stringstream
#include <stdlib.h>
#include <stdio.h>
#include <string>		// to_string
#include <cstring>		// strerror
#include <sys/socket.h>	// socket
#include <sys/types.h>
#include <unistd.h>		// getopt
#include <vector>		// vector
#include <iostream>

#include "mailbox.h"
#include "../library/socketcommunicator.h"

#define MYPORT 11000
#define BACKLOG 10
#define BUFFSIZE 1000
#define MAXTHREADS 100

int portno = MYPORT;
sockaddr_in masterAddr;
volatile bool print_dblog = false;		// Determines whether debug information is printed to the stderr.

pthread_t thread_arr[MAXTHREADS];		// Array of thread ID's.
volatile bool thread_avail[MAXTHREADS]; // States weather the thread with the corresponding index is active.

static pthread_mutex_t thread_avail_mutex = PTHREAD_MUTEX_INITIALIZER;	// Used to block access to thread_avail array.
static pthread_mutex_t storage_fd_mutex = PTHREAD_MUTEX_INITIALIZER;	// Only one thread can communicate with the the storage server at once.

volatile bool shutting_down = false;	// Signals whether the user has enter Ctrl+C and the server is in the process of shutting down.

enum state {USER, PASS, TRANS, UPD};	// All possible states in POP3 protocol.

int listen_fd = -1;			// Socket that listens for new client connections.
int storage_fd = -1;		// Socket that communicates with master storage server.
SocketCommunicator sockComm(storage_fd);

//--------------------------------------------------
// Dictionary (Ctrl + click to jump to functions of similar purpose)
//--------------------------------------------------
void setAddr(std::string line, char *ip, char *portno); 					// Reading command line arguments and server setup.
void send_wrapper(const char* msg, const int client_fd);					// General purpose helper functions.
void USER_response(const std::string user_arg, const int client_fd, state &curr_state, Mailbox &mbox);	// Handlers for various POP3 commands.

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
 * This function creates a sockaddr_in for the master server as specified in the configuration file.
 */
void setupStorageInfo(char* configFile)
{
	char portno[6] = {};				// Storage server's port number.
	char IP[16] = {};					// Storage server's IP address.

	std::ifstream in(configFile);
	std::string line = "";
	std::getline(in, line);
	setAddr(line, IP, portno);
	masterAddr = setupSockAddr(IP, portno);
}

/**
 * Parse command line arguments.
 * Set the port number and print debug output flag via pointers
 * that are passed into the function.
 * @param argc The number of arguments passed to main.
 * @param argv An  array of char[] corresponding to arguments passed to main.
 */
void get_cmd_opt(int argc, char*argv[]) {
	int opt;
	while ((opt = getopt(argc, argv, "p:av")) != -1) {
		switch(opt) {
			case 'p':
				portno = strtol(optarg, NULL, 10);
				if (portno == 0 || portno == LONG_MAX || portno == LONG_MIN) {
					fprintf(stderr, "Invalid port number.\r\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'a':
				fprintf(stderr, "Jialin Cai / caijia.\r\n");
				exit(EXIT_FAILURE);
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
	if (optind < argc) {
		setupStorageInfo(argv[optind]);
	} else {
		fprintf(stderr, "No server configuration file provided.\r\n");
		exit(EXIT_FAILURE);
	}
}

/**
 * Creates a server socket, binds it to a port, and listen for connections.
 * @listen_fd A pointer to the listening sockets file descriptor
 * which is updated by this function.
 */
void setup_server() {
	// Setup the socket addresses for later use.
	int status;
	struct addrinfo hints;
	struct addrinfo* servinfo;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	//--------------------
	// LISTENING SOCKET (communicates with front-end)
	//--------------------
	if ((status = getaddrinfo(NULL, std::to_string(portno).c_str(), &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo error (%s).\r\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}

	// Create a listening socket.
	listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if (listen_fd == -1) {
		fprintf(stderr, "Cannot open socket (%s).\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Free address and port immediately after program terminates.
	const int opt = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

	// Bind listening socket to port number.
	int bind_res = bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen);
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

	freeaddrinfo(servinfo);

	//--------------------
	// STORAGE SOCKET (communicates with back-end -- used with mutex)
	//--------------------
	storage_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (storage_fd == -1) {
		fprintf(stderr, "Thread cannot open socket (%s).\r\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	// Connect to storage server.
	connect(storage_fd, (struct sockaddr*) &masterAddr, sizeof(masterAddr));

	sockComm = SocketCommunicator(storage_fd);
}

/**
 * A wrapper function that sends a message to the client
 * and updates the debug log with the outgoing message or
 * error message if send() failed.
 */
void send_wrapper(const char* msg, const int client_fd) {
	int len = strlen(msg);
	int bytes_sent = send(client_fd, msg, len, 0);
	if (bytes_sent == -1) {
		fprintf(stderr, "Cannot send message to client (%s).\r\n", strerror(errno));
		return;
	}

	if (print_dblog) {
		fprintf(stderr, "[%d] N: %s", client_fd, msg);
	}
}

bool in_exp_state(const int client_fd, const state &curr_state, const state exp_state) {
	if (curr_state != exp_state) {
		const char* msg = "-ERR no mailbox name provided\r\n";
		send_wrapper(msg, client_fd);
		return false;
	}
	return true;
}

int str_to_idx(const std::string s_int, const int client_fd) {
	errno = 0;
	char* endptr;
	char* cmd_arg_arr = new char[s_int.length()];
	s_int.copy(cmd_arg_arr, s_int.length());
	long msg_idx = strtol(cmd_arg_arr, &endptr, 10);

	if (errno != 0 || endptr == cmd_arg_arr) {
		const char* msg = 	"-ERR Invalid message index\r\n";
		send_wrapper(msg, client_fd);
		fprintf(stderr, "%ld %s\n", msg_idx, s_int.c_str());
		return -1;
	}

	delete[] cmd_arg_arr;
	return msg_idx;
}

/**
 * This functions handles the necessary cleanup for when a thread is preparing to exit.
 * Cleans up memory allocated to the worker thread.
 * Updates thread status in thread_avail to true.
 * If the server is shutting down, print an error message.
 * @param arg An array of arguments containing 0) pointer to client file descriptor 1) this threads index
 */
static void thread_cleanup(void* arg) {
	int* arg_caste = (int*)arg;
	int client_fd = arg_caste[0];
	int i = arg_caste[1];

	if (shutting_down) {
		const char* msg;
		int len, bytes_sent;

		msg = "-ERR Server shutting down.\r\n";
		len = strlen(msg);
		bytes_sent = send(client_fd, msg, len, 0);
		if (bytes_sent == -1) {
			fprintf(stderr, "Cannot send message to client (%s).\r\n", strerror(errno));
		}
	}

	if (print_dblog) {
		fprintf(stderr, "[%d] Connection closed\r\n", client_fd);
	}

	close(client_fd);
	delete arg_caste;

	pthread_mutex_lock(&thread_avail_mutex);
	thread_avail[i] = true;
	pthread_mutex_unlock(&thread_avail_mutex);
}

/**
 * This function handles SIGINT.
 * Sets shutting down flag to true and signal for all threads to call call thread_cleanup and exit.
 */
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

/**
 * This function handles a USER command. If a valid username is given
 * during a valid state, the program moves into password checking state.
 */
void USER_response(const std::string user_arg, const int client_fd, state &curr_state, Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, USER)) {
		return;
	}

	std::string row = std::string(user_arg + "-mail");
	std::string col = std::string("mbox");

	pthread_mutex_lock(&storage_fd_mutex);
	sockComm.send_GET_request(row, col);
	bool GET_success = false;
	auto mbox_data = sockComm.parse_GET_response(GET_success);
	pthread_mutex_unlock(&storage_fd_mutex);

	if (GET_success) {
		curr_state = PASS;
		mbox.username = user_arg;
		mbox.mboxByteData = mbox_data;
		const char* msg = "+OK valid mailbox name\r\n";
		send_wrapper(msg, client_fd);
	} else {
		const char* msg = "-ERR never heard of mailbox name\r\n";
		send_wrapper(msg, client_fd);
	}
}

/**
 * This functions checks if the user entered a valid password
 * and loads the mbox contents from the file.
 */
void PASS_response(const std::string pass_arg, const int client_fd, state &curr_state, Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, PASS)) {
		return;
	}

	if (pass_arg != "cis505") {
		curr_state = USER;
		const char* msg = "-ERR invalid password\r\n";
		send_wrapper(msg, client_fd);
		return;
	}

	// Correct password - try to load mailbox content
	if(mbox.load_mbox() == false) {
		curr_state = USER;
		const char* msg = "-ERR unable to lock maildrop\r\n";
		send_wrapper(msg, client_fd);
		return;
	}
	curr_state = TRANS;
	const char* msg = "+OK maildrop locked and ready\r\n";
	send_wrapper(msg, client_fd);
}

void STAT_response(const int client_fd, const state &curr_state, const Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, TRANS)) {
		return;
	}

	// sum number of messages
	// and number total size
	size_t n_msgs = 0;
	size_t total_size = 0;
	for (auto &msg : mbox.msgs) {
		if (!msg.deleted) {
			n_msgs++;
			total_size += msg.byte_size;
		}
	}
	// Send totals to client
	std::stringstream msg_stream;;
	msg_stream << "+OK " << n_msgs << " " << total_size << "\r\n";
	send_wrapper(msg_stream.str().c_str(), client_fd);
}

void UIDL_noarg_response(const int client_fd, const state &curr_state, Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, TRANS)) {
		return;
	}

	std::string row = std::string(mbox.username + "-mail");
	std::string col = std::string("mbox");

	pthread_mutex_lock(&storage_fd_mutex);
	sockComm.send_GET_request(row, col);
	bool GET_success = false;
	auto mbox_data = sockComm.parse_GET_response(GET_success);
	pthread_mutex_unlock(&storage_fd_mutex);

	if (GET_success) {
		mbox.msgs.clear();
		mbox.mboxByteData = mbox_data;
	} else {
		const char* msg = "-ERR never heard of mailbox name\r\n";
		send_wrapper(msg, client_fd);
	}

	if(mbox.load_mbox() == false) {
		const char* msg = "-ERR unable to lock maildrop\r\n";
		send_wrapper(msg, client_fd);
		return;
	}

	// Write all none deleted msgs indices and ids to client
	std::stringstream msg_stream;
	msg_stream << "+OK unique-id listing follows\r\n";
	for (int i = 0 ; i < mbox.msgs.size() ; i++) {
		if (!mbox.msgs[i].deleted) {
			msg_stream << i + 1 << " " << mbox.msgs[i].id << "\r\n";
		}
	}
	// add termination sequence and send to client
	msg_stream << ".\r\n";
	send_wrapper(msg_stream.str().c_str(), client_fd);
}

void UIDL_arg_response(const std::string cmd_arg, const int client_fd, state &curr_state, const Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, TRANS)) {
		return;
	}

	// Convert the command argument into an integer.
	int msg_idx = str_to_idx(cmd_arg, client_fd);
	msg_idx--;	// Arrays index starting at zero, but msg number index starting at one.

	// +OK Message could be located. Send information to client.
	if (msg_idx >= 0
	 && msg_idx < mbox.msgs.size()
	 && !mbox.msgs[msg_idx].deleted) {
		std::stringstream msg_stream;
		msg_stream << "+OK " << msg_idx << " " << mbox.msgs[msg_idx].id << "\r\n";
		send_wrapper(msg_stream.str().c_str(), client_fd);
	// Index provided out of bounds or is that of deleted message.
	} else {
		const char* msg = "-ERR no such message\r\n";
		send_wrapper(msg, client_fd);
	}
}

void LIST_noarg_response(const int client_fd, const state &curr_state, const Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, TRANS)) {
		return;
	}

	// Compile list of non deleted indices and their size
	size_t msg_ct = 0;
	size_t octet_ct = 0;
	std::stringstream msg_stream_bullets;
	for (int i = 0 ; i < mbox.msgs.size() ; i++) {
		if (!mbox.msgs[i].deleted) {
			msg_stream_bullets << i + 1 << " " << mbox.msgs[i].byte_size << "\r\n";
			msg_ct ++;
			octet_ct += mbox.msgs[i].byte_size;
		}
	}
	// format final output
	std::stringstream msg_stream;
	msg_stream << "+OK " << msg_ct << " message (" << octet_ct << " octets)\r\n" << msg_stream_bullets.str();
	msg_stream << ".\r\n";

	send_wrapper(msg_stream.str().c_str(), client_fd);
}

void LIST_arg_response(const std::string cmd_arg, const int client_fd, const state &curr_state, const Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, TRANS)) {
		return;
	}

	// Convert the command argument into an integer.
	int msg_idx = str_to_idx(cmd_arg, client_fd);
	msg_idx--;	// Arrays index starting at zero, but msg number index starting at one.

	// Message could be located. Send information to client.
	if (msg_idx >= 0
	 && msg_idx < mbox.msgs.size()
	 && !mbox.msgs[msg_idx].deleted) {
		std::stringstream msg_stream;
		msg_stream << "+OK " << msg_idx << " " << mbox.msgs[msg_idx].byte_size << "\r\n";
		send_wrapper(msg_stream.str().c_str(), client_fd);
	// Index provided out of bounds or is that of deleted message.
	} else {
		const char* msg = "-ERR no such message\r\n";
		send_wrapper(msg, client_fd);
	}
}

void RETR_response(const std::string cmd_arg, const int client_fd, const state &curr_state, const Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, TRANS)) {
		return;
	}

	// Convert the command argument into an integer.
	int msg_idx = str_to_idx(cmd_arg, client_fd);
	msg_idx--;	// Arrays index starting at zero, but msg number index starting at one.

	// Message could be located. Send information to client.
	if (msg_idx >= 0
	 && msg_idx < mbox.msgs.size()
	 && !mbox.msgs[msg_idx].deleted) {
		std::string msg = std::string("+OK " + std::to_string(mbox.msgs[msg_idx].byte_size) + " octets\r\n");
		msg += mbox.msgs[msg_idx].body + std::string(".\r\n");
		send_wrapper(msg.c_str(), client_fd);
	// Index provided out of bounds or is that of deleted message.
	} else {
		const char* msg = "-ERR no such message\r\n";
		send_wrapper(msg, client_fd);
	}
}

void DELE_response(const std::string cmd_arg, const int client_fd, const state &curr_state, Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, TRANS)) {
		return;
	}

	// Convert the command argument into an integer.
	int msg_idx = str_to_idx(cmd_arg, client_fd);
	msg_idx--;	// Arrays index starting at zero, but msg number index starting at one.

	// Message could be located. Delete the message.
	if (msg_idx >= 0
	 && msg_idx < mbox.msgs.size()
	 && !mbox.msgs[msg_idx].deleted) {
		mbox.msgs[msg_idx].deleted = true;


		std::string msg = "+OK message deleted\r\n";
		send_wrapper(msg.c_str(), client_fd);
	// Index provided out of bounds or is that of deleted message.
	} else {
		const char* msg = "-ERR no such message\r\n";
		send_wrapper(msg, client_fd);
	}
}

void RSET_response(const int client_fd, const state &curr_state, Mailbox &mbox) {
	// Check correct state
	if (!in_exp_state(client_fd, curr_state, TRANS)) {
		return;
	}

	// mark all messages as undeleted
	size_t octet_ct;
	for (auto &msg : mbox.msgs) {
		msg.deleted = false;
		octet_ct += msg.byte_size;
	}
	std::stringstream msg_stream;
	msg_stream << "+OK maildrop has " << mbox.msgs.size() << " messages (" << octet_ct << " octets)\r\n";
	send_wrapper(msg_stream.str().c_str(), client_fd);
}

void QUIT_response(const int client_fd, state &curr_state, Mailbox &mbox, bool* connection_open) {
	std::string row(mbox.username + "-mail");
	std::string col("mbox");

	if (curr_state == TRANS) {
		curr_state = UPD;
		mbox.update_mboxByteData();

		pthread_mutex_lock(&storage_fd_mutex);
		sockComm.send_PUT_request(row, col, mbox.mboxByteData);
		bool PUT_success = sockComm.parse_PUT_response();
		pthread_mutex_unlock(&storage_fd_mutex);

		if (!PUT_success) {
			const char* msg = "-ERR deleted message not removed; localhost server signing off\r\n";
			send_wrapper(msg, client_fd);
			*connection_open = false;
			return;
		}
	}

	const char* msg = "+OK localhost server signing off\r\n";
	send_wrapper(msg, client_fd);
	*connection_open = false;
}

/**
 * Given a command such as HELO domain_name this function returns the argument
 * of the command. ie domain_name.
 */
std::string get_cmd_arg(const std::string line, int cmd_len) {
	std::string cmd_arg;
	line.length() > cmd_len ? cmd_arg = line.substr(cmd_len) : cmd_arg = "";
	return cmd_arg;
}

/**
 * Sends a message to the client via the specified file descriptor.
 * Updates the connection_open flag if the client decides to close the connection.
 * @param line The message to be sent.
 * @param client_fd The file descriptor of the client.
 * @param connection_open A flag that is updated if the client wants to close
 * the connection.
 */
void process_cmd(const std::string line, const int client_fd, bool* connection_open,
				 state &curr_state, Mailbox &mbox) {

	std::string trim_line = line.substr(0, line.length() - 2);	// remove <CRLF> from command line

	// USER
	if (trim_line.find("USER ") == 0) {
		std::string cmd_arg = get_cmd_arg(trim_line, sizeof("USER ") - 1);
		USER_response(cmd_arg, client_fd, curr_state, mbox);
	}

	// PASS
	else if (trim_line.find("PASS ") == 0) {
		std::string cmd_arg = get_cmd_arg(trim_line, sizeof("PASS ") - 1);
		PASS_response(cmd_arg, client_fd, curr_state, mbox);
	}

	// STAT
	else if (trim_line == "STAT") {
		STAT_response(client_fd, curr_state, mbox);
	}

	// UIDL no arg
	else if (trim_line == "UIDL") {
		UIDL_noarg_response(client_fd, curr_state, mbox);
	}

	// UIDL with arg
	else if (trim_line.find("UIDL ") == 0) {
		std::string cmd_arg = get_cmd_arg(trim_line, sizeof("UIDL ") - 1);
		UIDL_arg_response(cmd_arg, client_fd, curr_state, mbox);
	}

	// LIST no arg
	else if (trim_line == "LIST") {
		LIST_noarg_response(client_fd, curr_state, mbox);
	}

	// LIST with arg
	else if (trim_line.find("LIST ") == 0) {
		std::string cmd_arg = get_cmd_arg(trim_line, sizeof("LIST ") - 1);
		LIST_arg_response(cmd_arg, client_fd, curr_state, mbox);
	}

	// RETR
	else if (trim_line.find("RETR ") == 0) {
		std::string cmd_arg = get_cmd_arg(trim_line, sizeof("RETR ") - 1);
		RETR_response(cmd_arg, client_fd, curr_state, mbox);
	}

	// DELE
	else if (trim_line.find("DELE ") == 0) {
		std::string cmd_arg = get_cmd_arg(trim_line, sizeof("DELE ") - 1);
		DELE_response(cmd_arg, client_fd, curr_state, mbox);
	}

	// RSET
	else if (trim_line == "RSET") {
		RSET_response(client_fd, curr_state, mbox);
	}

	// NOOP
	else if (trim_line == "NOOP") {
		const char* msg = "+OK\r\n";
		send_wrapper(msg, client_fd);
	}

	// QUIT
	else if (trim_line == "QUIT") {
		QUIT_response(client_fd, curr_state, mbox, connection_open);
	}

	else {
		const char* msg = "-ERR unrecognized command\r\n";
		send_wrapper(msg, client_fd);
	}
}

/**
 * A thread function that continuously checks for incoming messages at a
 * client socket and echos the input. This function closes the socket
 * file descriptor when the client instructs to close the connection.
 * @ client_fd The file descriptor of the client socket.
 */
static void* thread_handle_client(void* arg) {
	// Ensure thread_cleanup function is popped on the stack
	// for when this function exits.
	pthread_cleanup_push(thread_cleanup, arg);

	int* arg_caste = (int*)arg;
	int client_fd = arg_caste[0];	// client file descriptor
	int i = arg_caste[1];			// the index of this thread's ID in thread_arr.

	// Send a "Server ready" response to client
	// to a signal successful connection.
	const char* msg = "+OK POP3 ready [localhost]\r\n";
	send_wrapper(msg, client_fd);

	std::string line;			// A command that is "built up" from characters in char_buf
								// until the <CRLF> characters are encounter.
								// At which point the command is handled and string is cleared to an empty string.

	char char_buf[BUFFSIZE];	// Each time recv() is called, char_buf refilled.

	state curr_state = USER;

	Mailbox mbox = Mailbox();

	bool connection_open = true;
	while (connection_open) {
		int bytes_read = recv(client_fd, &char_buf[0], BUFFSIZE, 0);	// Block and wait for responses from client.

		// Client closed connection.
		if (bytes_read == 0 || bytes_read == -1) {
			fprintf(stderr, "Client closed connection.\r\n");
			connection_open = false;
		}

		// Process the bytes that were read
		// and prepare to read again.
		else {
			std::string tmp(char_buf);
			int prev_linefeed_pos = 0;
			for (int i = 0; i < bytes_read; i++) {
				if (i != 0 && char_buf[i] == '\n' && char_buf[i-1] == '\r') {
					std::string to_linefeed = tmp.substr(prev_linefeed_pos, i - prev_linefeed_pos + 1);
					line += to_linefeed;

					if (print_dblog) {
						fprintf(stderr, "[%d] C: %s", client_fd, line.c_str());
					}

					process_cmd(line, client_fd, &connection_open, curr_state, mbox);
					line = std::string();
					prev_linefeed_pos = i + 1;
				}
			}
			if (prev_linefeed_pos < bytes_read) {
				line += tmp.substr(prev_linefeed_pos, bytes_read - prev_linefeed_pos);
			}
		}
	}

	pthread_cleanup_pop(1);
	pthread_exit(NULL);
}

/*
 * used to connect to a server with indicated port number
 */
int connect_server(int port) {
	int fd = socket(PF_INET, SOCK_STREAM, 0);

	// Return error when sockfd < 0
	if (fd < 0) {
		fprintf(stderr, "Cannot open socket (%s)\n", strerror(errno));
		exit(1); // cannot open socket error
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &(addr.sin_addr));
	connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	return fd;
}

/**
 * Connects to the backend master. When a new primary is selected, the master will alert this thread
 * which updates the global variable storage_fd.
 */
static void *thread_handle_updateStorageSocket(void *arg) {
	// Create a TCP socket soley for communicating a new primary.
	int newPrimary_fd = connect_server(10000);

	char char_buf[BUFFSIZE];
	while (!shutting_down) {
		int bytes_read = recv(newPrimary_fd, &char_buf[0], BUFFSIZE, 0);	// Block and wait for a new primary alert from master
		int newPrimaryPortno = strtoull(char_buf, NULL, 10);

		close(storage_fd);
		storage_fd = connect_server(newPrimaryPortno);
	}

	pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	// Bind the SIGINT handler
	struct sigaction new_action;
	new_action.sa_handler = sigint_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 1;

	sigaction(SIGINT, &new_action, NULL);

	// All threads are initially available.
	for (auto &status : thread_avail) {
		status = true;
	}

	get_cmd_opt(argc, argv);
	setup_server();

	pthread_t newPrimary_thread;
	pthread_create(&newPrimary_thread, NULL, thread_handle_updateStorageSocket, nullptr);

	while(!shutting_down) {
		struct sockaddr_storage client_addr;
		socklen_t client_addr_size = sizeof(client_addr);

		int* client_fd = new int[2];
		client_fd[0] = accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_size);

		if (client_fd[0] == -1) {
			if (shutting_down) {
				delete[] client_fd;
				break;
			}
			fprintf(stderr, "Accepting client failed (%s).\r\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (print_dblog) {
			fprintf(stderr, "[%d] New connection\r\n", *client_fd);
		}

		for (int i = 0; i < MAXTHREADS; i++) {
			if (thread_avail[i] == true) {
				client_fd[1] = i;
				pthread_create(&thread_arr[i], NULL, thread_handle_client, client_fd);
				pthread_mutex_lock(&thread_avail_mutex);
				thread_avail[i] = false;
				pthread_mutex_unlock(&thread_avail_mutex);
				break;
			}
		}
	}

	exit(EXIT_SUCCESS);
}
