#include <iostream>
#include <netdb.h>      // addrinfo
#include <netinet/in.h> // AF_INET6
#include <stdio.h>
#include <stdlib.h>
#include <string>       // to_string
#include <sys/socket.h> // socket
#include <sys/types.h>
#include <unistd.h> 	// getopt
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <vector>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <set>
#include <utility>

#define PORT 8004
#define DATAGRAM_PORT 8010
#define SOCK_NUM 100
#define NUM_SERVERS 3
#define BUFF_SIZE 100

using namespace std;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

unordered_set<int> ports = {8000, 8001, 8002};
unordered_map<int, unordered_set<int>> connections;
unordered_map<int, int> fds;

typedef struct thread_args {

	int* fd;
	sockaddr_in* addr;

} thread_args;


void* worker(void* arg) {

	for (int port : ports) cout << port << endl;

	pthread_detach(pthread_self());

	thread_args args = *(thread_args*) arg;
	int comm_fd = *(args.fd);
	free(args.fd);
	int port = args.addr->sin_port;

	string send_port = "Give port or enter any num\r\n";
	write(comm_fd, send_port.c_str(), send_port.size());

	char buf[100];
	read(comm_fd, buf, 100);
	port = atoi(buf);

	if (ports.find(port) != ports.end()) {
		// connection is frontend server

		unordered_set<int> peers;
		connections[port] = peers;
		fds[port] = comm_fd;


		string heartbeat = "+heart\r\n";
		fd_set set;
		struct timeval timeout;
		int rv = 1;
		char buff[100];
		int len = 100;

		while (rv > 0) {

			write(comm_fd, heartbeat.c_str(), heartbeat.size());
			sleep(1);

			FD_ZERO(&set); /* clear the set */
			FD_SET(comm_fd, &set); /* add our file descriptor to the set */

			timeout.tv_sec = 3;
			timeout.tv_usec = 0;

			rv = select(comm_fd + 1, &set, NULL, NULL, &timeout);
			if(rv == -1)
				perror("select"); /* an error accured */
			else if(rv == 0)
				printf("timeout"); /* a timeout occured */
			else {
				read(comm_fd, buff, len);
				printf("Data read successfully\r\n");
			}
		}

		pthread_mutex_lock(&mutex);

		unordered_set<int> clients = connections[port];
		connections.erase(port);
		close(fds[port]);
		fds.erase(port);
		int minLen = 10000;
		int minPort = -1;

		for (auto& pair : connections) {
			if (pair.second.size() < minLen) {
				minPort = pair.first;
				minLen = pair.second.size();
			}
		}

		for (int client : clients) {
			connections[minPort].insert(client);
			write(fds[minPort], to_string(client).c_str(), to_string(client).size());
		}

		pthread_mutex_unlock(&mutex);


	} else {
		// connection is client

		pthread_mutex_lock(&mutex);

		int minLen = 10000;
		int minPort = -1;

		for (auto& pair : connections) {
			if (pair.second.size() < minLen) {
				minPort = pair.first;
				minLen = pair.second.size();
			}
		}

		connections[minPort].insert(port);

		write(fds[minPort], to_string(port).c_str(), to_string(port).size());
		printf("Informed %d of new client %d\r\n", minPort, port);
		pthread_mutex_unlock(&mutex);


	}
	pthread_exit(NULL);
}

int main (int argc, char* argv[]) {


	// create the sock
	int sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "Error creating socket\n");
		exit(1);
	}

	// set up the server address and port number
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
	servaddr.sin_port = htons(PORT);

	// set up reuse port and address so our bind does not fail
	const int change = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &change, sizeof(int)) < 0) {
		fprintf(stderr, "Error setting socket opt\n");
		exit(3);
	}

	const int change_2 = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &change_2, sizeof(int)) < 0) {
		fprintf(stderr, "Error setting socket opt\n");
		exit(3);
	}

	if (bind(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) < 0) {
		fprintf(stderr, "Failure to bind\n");
		exit(3);
	}

	// listen for a connection.
	if (listen(sockfd, SOCK_NUM) < 0) {
		fprintf(stderr, "Error when listening\n");
		exit(2);
	}

	// accept connections until server is killed.
	while (true) {

		// set up client structs
		struct sockaddr_in clientaddr;
		socklen_t clientaddr_len = sizeof(clientaddr);
		int* fd = (int*) malloc(sizeof(int));

		// accept a connection into malloced memory.
		*fd = accept(sockfd, (struct sockaddr*) &clientaddr, &clientaddr_len);
		if (*fd < 0) {
			free(fd);
			fprintf(stderr, "Error accepting connection\n");
			exit(3);
		}

		pthread_t pid;
		thread_args args;
		args.addr = &clientaddr;
		args.fd = fd;

		pthread_create(&pid, NULL, &worker, &args);

	}

	exit(0);
}
