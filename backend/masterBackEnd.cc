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

#define PORT 10000
#define DATAGRAM_PORT 10010
#define SOCK_NUM 100
#define BUFF_SIZE 50

using namespace std;

string primary_addr = "just start, no address";
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

set<int> all_fds;

string addr_to_string(sockaddr_in addr) {

	string toReturn;
	toReturn += to_string(addr.sin_addr.s_addr);
	toReturn += ':';
	toReturn += to_string(addr.sin_port);

	return toReturn;
}

void* heartbeat_worker(void* arg) {

	pthread_detach(pthread_self());

	// creating socket for heartbeat thread
	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		fprintf(stderr, "Cannot open socket (%s)\n", strerror(errno));
		exit(1);
	}

	// binding to address
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
	servaddr.sin_port = htons(DATAGRAM_PORT);
	bind(sock, (struct sockaddr*)&servaddr, sizeof(servaddr));

	while (true) {

		// setting up address of source of message
		struct sockaddr_in src;
		socklen_t srclen = sizeof(src);
		char buf[100];

		int rlen = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&src, &srclen);

		string new_addr(buf);

		if (new_addr != primary_addr) {
			// if the address sent is not what we have in store

			fprintf(stderr, "New primary detected\r\n");

			// set the curr address to new address
			primary_addr = new_addr;

			// set of file descriptors to remove
			set<int> to_delete;

			pthread_mutex_lock(&mutex);

			// we send the new ip to every frontend server, if we are unable to, we remove the frontend from our list
			for (int fd : all_fds) {
				if (write(fd, primary_addr.c_str(), primary_addr.size()) <= 0) {
					to_delete.insert(fd);
				}

				printf("Sent %s to connection %d\n", primary_addr.c_str(), fd);

			}

			// we close and remove the dead frontend servers
			for (int fd : to_delete) {
				close(fd);
				all_fds.erase(fd);
			}
			pthread_mutex_unlock(&mutex);

		}
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

	pthread_t heartID;
	pthread_create(&heartID, NULL, &heartbeat_worker, NULL);

	// accept connections until server is killed.
	while (true) {

		// set up client structs
		struct sockaddr_in clientaddr;
		socklen_t clientaddr_len = sizeof(clientaddr);
		int* fd = (int*) malloc(sizeof(int));

		// accept a connection into malloced memory.
		*fd = accept(sockfd, (struct sockaddr*) &clientaddr, &clientaddr_len);
		if (*fd < 0) {
			continue;
		} else {
			pthread_mutex_lock(&mutex);
			all_fds.insert(*fd);
			pthread_mutex_unlock(&mutex);
			write(*fd, primary_addr.c_str(), primary_addr.size());
		}
	}

	exit(0);
}
