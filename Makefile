TARGETS = storageserver storageserver2 frontendserver smtp pop3 masterBackEnd masterFrontEnd

all: $(TARGETS)

message.o: ./backend/message.cc
	g++ -g -c $^

storageserver: ./backend/storageserver.cc message.o socketcommunicator.o
	g++ $^ -lpthread -g -lcrypto -o $@

storageserver2: ./backend/storageserver2.cc message.o socketcommunicator.o
	g++ $^ -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -lpthread -g -o $@

masterBackEnd: ./backend/masterBackEnd.cc
	g++ $^ -lpthread -g -o $@

masterFrontEnd: ./frontend/masterFrontEnd.cc
	g++ $^ -lpthread -g -o $@

mailbox.o: ./mail/mailbox.cc
	g++ -g -c $^

smtp: ./mail/smtp.cc socketcommunicator.o
	g++ $^ -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -lpthread -g -o $@

pop3: ./mail/pop3.cc mailbox.o socketcommunicator.o
	g++ $^ -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -lpthread -g -o $@
	
socketcommunicator.o: ./library/socketcommunicator.cc
	g++ -g -c -lcrypto $^

frontendserver: ./frontend/frontendserver.cc socketcommunicator.o
	g++ $^ -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -lpthread -g -o $@

clean::
	rm -fv $(TARGETS) *~ *.o
