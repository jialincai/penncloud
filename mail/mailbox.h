/*
 * Mailbox.h
 *
 *  Created on: Oct 13, 2022
 *  Author: Jialin Cai
 */

#ifndef MAILBOX_H_
#define MAILBOX_H_

#include <string>
#include <vector>

struct Message {
	std::string id;
	std:: string header;
	std::string body;
	size_t byte_size;
	bool deleted;
};

class Mailbox {
//--------------------------------------------------------------------------------
// Member variables
//--------------------------------------------------------------------------------
public:
	std::string username;
	std::vector<char> mboxByteData;
	std::vector<Message> msgs;
public:
//--------------------------------------------------------------------------------
// Constructors // Destructors
//--------------------------------------------------------------------------------
	Mailbox();
	virtual ~Mailbox();

//--------------------------------------------------------------------------------
// Member Functions
//--------------------------------------------------------------------------------
	/**
	 * Loads all the messages in a .mbox file into memory.
	 */
	bool load_mbox();

	/**
	 * Writes all the changes that occurred during the transaction session back to mbox file.
	 */
	void update_mboxByteData();
};
//--------------------------------------------------------------------------------
// Static Functions
//--------------------------------------------------------------------------------
/**
 * Converts a string into a Message struct.
 */
Message to_message(std::string line);

/**
 * The digest will be written to digestBuffer, which must be at least MD5_DIGEST_LENGTH bytes long
 */
void computeDigestX(char *data, int dataLengthBytes, unsigned char *digestBuffer);

/**
 * Generates a Hex-string of length 32 from a given string.
 */
std::string generate_idX(std::string line);

#endif /* MAILBOX_H_ */
