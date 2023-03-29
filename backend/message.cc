/*
 * message.cpp
 *
 *  Created on: Nov 22, 2022
 *      Author: cis5050
 */

#include "message.h"

Message::Message() : type(NONE), row(""), col(""), v1(""), v2(""), v1BytesToRead(0), v2BytesToRead(0)
{}

Message::~Message() {
	// TODO Auto-generated destructor stub
}

void Message::clear()
{
	*this = Message();
}

