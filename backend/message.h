/*
 * message.h
 *
 *  Created on: Nov 22, 2022
 *      Author: cis5050
 */

#ifndef BACKEND_MESSAGE_H_
#define BACKEND_MESSAGE_H_

#include <string>

enum Type {NONE, PUT, GET, CPUT, DEL};

class Message {
public:
	Type type;
	std::string row;
	std::string col;
	std::string v1;
	std::string v2;
	unsigned long long v1BytesToRead;
	unsigned long long v2BytesToRead;
public:
	Message();
	virtual ~Message();

	void clear();
};

#endif /* BACKEND_MESSAGE_H_ */
