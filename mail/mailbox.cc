/*
 * Mailbox.cpp
 *
 *  Created on: Oct 13, 2022
 *  Author: Jialin Cai
 */

#include "mailbox.h"
#include <stdio.h>
#include <sys/file.h>	// flock
#include <openssl/md5.h>// for hashing
#include <iostream>
#include <fstream>

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;	// Used to block multi-thread access to a file.

#define BUFFSIZE 1000

Mailbox::Mailbox() : username(""), mboxByteData(std::vector<char>()), msgs(std::vector<Message>())
{}

Mailbox::~Mailbox()
{}

bool Mailbox::load_mbox() {
	unsigned long long end_of_prev_msg = 0;
	for (int i = 0; i < mboxByteData.size(); i++) {
		if (i >= 4 && mboxByteData[i] == '\n'	// Find termination sequence in buffer.
				   && mboxByteData[i-1] == '\r'
				   && mboxByteData[i-2] == '.'
				   && mboxByteData[i-3] == '\n'
				   && mboxByteData[i-4] == '\r') {
			std::string msg = std::string(mboxByteData.begin() + end_of_prev_msg, mboxByteData.begin() + i);

			// Send message string to be converted into message struct
			// and added to this mailbox array of messages.
			msgs.push_back(to_message(msg));
			end_of_prev_msg = i + 1;
		}
	}

	return true;
}

void Mailbox::update_mboxByteData() {
	// Write the modified mailbox to a vector array and send a PUT request to the storage server.
	mboxByteData.erase(mboxByteData.begin(), mboxByteData.end());
	for (auto msg : msgs) {
		if (!msg.deleted) {
//			for (char &c : msg.header) {
//				mboxByteData.push_back(c);
//			}

			for (char &c : msg.body) {
				mboxByteData.push_back(c);
			}
			mboxByteData.push_back('\r');
			mboxByteData.push_back('\n');
			mboxByteData.push_back('.');
			mboxByteData.push_back('\r');
			mboxByteData.push_back('\n');
		}
	}
}

Message to_message(std::string line) {
	Message m = Message();

	// Generate id
	m.id = generate_idX(line.substr(0, line.length() - 3));	// remove .<CRLF> when calculating height message size
															// but keep it in the message body. This makes the RETR
															// command less cumbersome.

	int body_begin_i = line.find("\r\n") + 2;
	std::string header = line.substr(0, body_begin_i);
//	std::string body = line.substr(body_begin_i);

//	m.header = header;
//	m.body = body;
//	m.byte_size = body.length() - 3;
//	m.deleted = false;

	m.header = header;
	m.body = line;
	m.byte_size = line.length() - 3;
	m.deleted = false;


	return m;
}

std::string generate_idX(std::string line) {
	char* data = new char[line.length() + 1];
	line.copy(data, line.length());

	unsigned char digestBuffer[MD5_DIGEST_LENGTH];
	computeDigestX(data, line.length(), digestBuffer);

	std::string result;
	for (size_t i = 0 ; i < 17 ; i++) {
		result += "0123456789ABCDEF"[digestBuffer[i] / 16];
		result += "0123456789ABCDEF"[digestBuffer[i] % 16];
	}

	delete[] data;
	return result;
}

void computeDigestX(char *data, int dataLengthBytes, unsigned char *digestBuffer)
{
  /* The digest will be written to digestBuffer, which must be at least MD5_DIGEST_LENGTH bytes long */
  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, data, dataLengthBytes);
  MD5_Final(digestBuffer, &c);
}

