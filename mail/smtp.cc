#include <climits>		// LONG_MAX, LONG_MIN
#include <csignal>		// signal
#include <ctime>		// time_t
#include <errno.h>		// errno
#include <fstream>		// ifstream
#include <arpa/inet.h>	// inet_pton
#include <netdb.h>		// addrinfo
#include <netinet/in.h>	// AF_INET6
#include <stdlib.h>
#include <stdio.h>
#include <string>		// to_string
#include <cstring>		// strerror
#include <sys/file.h>	// flock
#include <sys/socket.h>	// socket
#include <sys/types.h>
#include <unistd.h>		// getopt
#include <vector>		// vector
#include <iostream>

#include "../library/socketcommunicator.h"

#define MYPORT 2500
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

enum state {NONE, INIT, MAIL_FROM, RCPT_TO, DATA};	// All possible states in SMTP protocol.

// A structure holds the necessary information associated with an email.
// Ie. sender name, recipient names, and message text.
struct MailInfo{
	std::string sender;
	std::vector<std::string> recipients;
	std::string text;
	std::string time;
};

int listen_fd = -1;			// Socket that listens for new client connections.
int storage_fd = -1;		// Socket that communicates with master storage server.
SocketCommunicator sockComm(storage_fd);

//--------------------------------------------------
// Dictionary (Ctrl + click to jump to functions of similar purpose)
//--------------------------------------------------
void setAddr(std::string line, char *ip, char *portno); 					// Reading command line arguments and server setup.
void send_wrapper(const char* msg, const int client_fd);					// General purpose helper functions.
void send_GET_request(const std::string row, const std::string col);		// Communication with backend storager server.
static void thread_cleanup(void* arg);										// Functions related to signals and thread cleanup.
void HELO_response(const std::string domain_name, const int client_fd, state &curr_state);	// Handlers for various SMTP commands.
void process_cmd(const std::string line, const int client_fd, bool* connection_open,
				 state &curr_state, MailInfo &mail_info);									// Major thread functions.
int main(int argc, char *argv[]);											// Primary thread of execution.


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
 * Set the port number and print debug output flag.
 * Extract addresses and port numbers of storage servers from configuration folder.
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
 * Creates a listening socket, binds it to a port, and waits for new connections from clients.
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

std::string get_timestamp() {
	std::time_t t = std::time(nullptr);
	char time_arr[100];
	strftime(time_arr, sizeof(time_arr), "%c", std::localtime(&t));
	return std::string(time_arr);
}

std::string get_cmd_arg(const std::string line, int cmd_len) {
	std::string cmd_arg;
	line.length() > cmd_len ? cmd_arg = line.substr(cmd_len) : cmd_arg = "";
	return cmd_arg;
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
		fprintf(stderr, "[%d] \r\n", client_fd);
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
 * client command HELO <domain name> response handler
 * @param line domain_name
 * @param cmds_recv An array of flag indicating whether a commands has been previously recieved.
 * @param clien_fd The file descriptor to the client.
 */
void HELO_response(const std::string domain_name, const int client_fd, state &curr_state) {
	// Check domain_name is not empty string
	if (domain_name == "") {
		const char* msg = "501 No domain provided\r\n";
		send_wrapper(msg, client_fd);
		return;
	}

	// HELO is valid only when the session is in its beginning or initial state
	// ie. The only other logged command is a previous HELO command.
	if (curr_state == NONE || curr_state == INIT) {
		const char* msg = "250 localhost\r\n";
		send_wrapper(msg, client_fd);
		curr_state = INIT;
	// Invalid sequence
	} else {
		const char* msg = "503 Bad sequence of commands\r\n";
		send_wrapper(msg, client_fd);
	}
}

/**
 * client command HELO <domain name> response handler
 * @param line sender
 * @param client_fd The file descriptor to the client.
 * @param cmds_recv Pointer to an array of flags indicating whether a command has been previously received.
 * @param mail_info A reference to the an array containing message sender, recipient, and text.
 */
void MAIL_FROM_response(const std::string sender_addr, const int client_fd, state &curr_state, MailInfo &mail_info) {
	// Check that the sender name is valid
	if (sender_addr != ""
	 && sender_addr.find("@") != sender_addr.npos
	 && sender_addr.find("@") != 1
	 && sender_addr.substr(sender_addr.find("@")) != ">") {
		// Session has not been initialized.
		if (curr_state == NONE) {
			const char* msg = "503 Bad sequence of commands\r\n";
			send_wrapper(msg, client_fd);
			return;
		// Session has been initialized, but we're in the midst of a transaction.
		} else if (curr_state != INIT) {
			// Wipe all mail information from the current transaction.
			mail_info = MailInfo();
		}

		// Session has just been initialized or wiped.
		// Update state and mail information. Signal success.
		curr_state = MAIL_FROM;
		mail_info.sender = sender_addr;

		const char* msg = "250 OK\r\n";
		send_wrapper(msg, client_fd);
		return;
	}

	// Invalid sender name
	const char* msg = "501 Invalid source mailbox\r\n";
	send_wrapper(msg, client_fd);
}

void RCPT_TO_response(const std::string rcpt_addr, const int client_fd, state &curr_state, MailInfo &mail_info) {
	// Check that the recipient name is valid
	if (rcpt_addr != ""
	 && rcpt_addr.find("@") != 1
	 && rcpt_addr.find("@localhost>") == rcpt_addr.length() - 11) {

		std::string username = rcpt_addr.substr(1, rcpt_addr.length() - sizeof("@localhost>"));

		// RCPT_TO must be relayed after HELO and MAIL FROM
		if (curr_state == MAIL_FROM || curr_state == RCPT_TO) {
			curr_state = RCPT_TO;
			mail_info.recipients.push_back(username);

			const char* msg = "250 OK\r\n";
			send_wrapper(msg, client_fd);
		// MAIL FROM has command has not been entered
		} else {
			const char* msg = "503 Bad sequence of commands\r\n";
			send_wrapper(msg, client_fd);
		}
	// Recipient name not valid
	} else {
		const char* msg = "553 Requested action  not taken: mailbox name not allowed\r\n";
		send_wrapper(msg, client_fd);
	}
}

void DATA_response(const int client_fd, state &curr_state) {
	// Check that we're in RCPT_TO state.
	// Jump into DATA writing state.
	if (curr_state == RCPT_TO) {
		curr_state = DATA;
		const char* msg = "354 Start mail input; end with <CRLF>.<CRLF>\r\n";
		send_wrapper(msg, client_fd);
	// Any other state is invalid.
	} else {
		const char* msg = "503 Bad sequence of commands\r\n";
		send_wrapper(msg, client_fd);
	}
}

/**
 * Write the data stored in mail_info to the mailbox specified.
 */
void write_to_mbox(const int client_fd, state &curr_state, MailInfo &mail_info, const int storage_fd) {
	// As long as one rcpt successfully gets message - command returns success
	bool success = false;

	// For each recipient, get their mbox from the storage server and append the new message.
	for (auto &username : mail_info.recipients) {
		std::string row = std::string(username + "-mail");
		std::string col = std::string("mbox");

		// Fetch the current mbox contents from storage server.
		pthread_mutex_lock(&storage_fd_mutex);
		sockComm.send_GET_request(row, col);

		bool GET_success = false;
		auto mbox_data = sockComm.parse_GET_response(GET_success);

		if (!GET_success) {
			continue;
		}

		std::string newMsg = std::string("From " + mail_info.sender + " " + mail_info.time + "\r\n");
		newMsg += std::string(mail_info.text + "\r\n");

		for (char const& c : newMsg) {
			mbox_data.push_back(c);
		}

		sockComm.send_PUT_request(row, col, mbox_data);

		if (sockComm.parse_PUT_response() == true) {
			success = true;
		}

		pthread_mutex_unlock(&storage_fd_mutex);
	}


	if (success) {
		const char* msg = "250 OK\r\n";
		send_wrapper(msg, client_fd);
	} else {
		const char* msg = "554 transaction failed\r\n";
		send_wrapper(msg, client_fd);
	}

	// Jump back to init state and clear information from the current session
	curr_state = INIT;
	mail_info = MailInfo();
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
				 state &curr_state, MailInfo &mail_info) {
	// If the transaction is currently in the data state
	// all input should be appended to mail text without further processing.
	if (curr_state == DATA) {
		mail_info.text += line;

		// Termination sequence <CRLF>.<CRLF> has been encountered.
		if (mail_info.text.find("\r\n.\r\n") != mail_info.text.npos) {

			mail_info.time = get_timestamp();
			write_to_mbox(client_fd, curr_state, mail_info, storage_fd);
		}
		return;
	}

	std::string trim_line = line.substr(0, line.length() - 2);	// remove <CRLF> from command line
	// HELO
	if (trim_line.find("HELO ") == 0) {
		std::string cmd_arg = get_cmd_arg(trim_line, sizeof("HELO ") - 1);
		HELO_response(cmd_arg, client_fd, curr_state);
	}

	// MAIL FROM:
	else if (trim_line.find("MAIL FROM:") == 0) {
		std::string cmd_arg = get_cmd_arg(trim_line, sizeof("MAIL FROM:") - 1);
		MAIL_FROM_response(cmd_arg, client_fd, curr_state, mail_info);
	}

	// RCPT TO:
	else if (trim_line.find("RCPT TO:") == 0) {
		std::string cmd_arg = get_cmd_arg(trim_line, sizeof("RCPT TO:") - 1);
		RCPT_TO_response(cmd_arg, client_fd, curr_state, mail_info);
	}

	// DATA
	else if (trim_line == "DATA") {
		DATA_response(client_fd, curr_state);
	}

	// QUIT
	else if (trim_line == "QUIT") {
		const char* msg = "221 localhost Service closing transmission channel\r\n";
		send_wrapper(msg, client_fd);
		*connection_open = false;
	}

	// RSET
	else if (trim_line == "RSET") {
		// Reset state to INIT and clear all current mail information.
		if (curr_state != NONE && curr_state != INIT) {
			curr_state = INIT;
			mail_info = MailInfo();
		}

		const char* msg = "250 OK\r\n";
		send_wrapper(msg, client_fd);
	}

	// NOOP
	else if (trim_line == "NOOP") {
		const char* msg = "250 OK\r\n";
		send_wrapper(msg, client_fd);
	}

	// All other commands are not supported
	else {
		const char* msg = "500 Syntax error, command unrecognized\r\n";
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
	const char* msg = "220 localhost Server ready\r\n";
	send_wrapper(msg, client_fd);

	std::string line;			// A command that is "built up" from characters in char_buf
								// until the <CRLF> characters are encounter.
								// At which point the command is handled and string is cleared to an empty string.

	char char_buf[BUFFSIZE];	// Each time recv() is called, char_buf refilled.

	state curr_state = NONE;

	MailInfo mail_info = MailInfo();

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

					process_cmd(line, client_fd, &connection_open, curr_state, mail_info);
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

	// NOTIFY MASTER THIS IS NODE NEEDS TO BE ALERTED IF PRIMARY CHANGES

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
