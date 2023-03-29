#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <algorithm>
#include <pthread.h>
#include <signal.h>
#include <mutex>
#include <sys/socket.h>
#include <vector>
#include <set>
#include <cerrno>
#include <ctype.h>
#include <fstream>
#include <sstream>
#include <map>

#include "../library/socketcommunicator.h"

using namespace std;


//html file
//HEADER: format
//react
//cookie
//GET, POST, HEAD
// signal handler

struct Mail {
	string id;
	string sender;
	string date;
	string msg;
	string subject;

};

int servfd;
//int pop3_fd;
//int storage_fd;
map<int, string> cookies_dic;
map<int, bool> logged_in;
//map<int, int> storage_fds;
map<string, string> current_paths;
map<int, int> stor_fds;
map<int, int> pop3_fds;
map<int, int> smtp_fds;
map<int, bool> initialized;
map<int, map<int, Mail>> mailboxes;

int fds[100];
int num_threads=0;
bool vFlag = false;
string pass = "";
char no_url_error[20] = "No url entered\n";
char no_http_error[20] = "no HTTP version\n";
//map<int, string> cookies_table; // save cookie_id and username; only exists when it's logged in

string ok = "200 OK\r\n";
string notFound = "HTTP/1.1 404 Not Found\r\n";
string badRequest = "400 Bad Request";

#define MYPORT 10001
#define STORAGEPORT 10000
#define POP3PORT 11000
#define SMTPPORT 2500
#define MASTERFRONT 8004

int storage_fd = -1;

//--------------------------------------------------
// Dictionary (Ctrl + click to jump to functions of similar purpose)
//--------------------------------------------------

//open page
string open_page(string path);
string open_page_with_edit(string path, string marker, string toInsert);
void render_page(string page, int fd);
void render_page_with_cookie(string content, int fd, string cookie, string pagename);
void render_next_page(string content, int fd, string pagename, string curr_path);
void render_page_content_type(string content, int fd, string contenttype);

//perform actions
//void get_handler(char *current, int fd, int sid);
int check_login(string username, string password, int fd);
int create_new_user(string username, string password, int fd);
int change_user(string username, string password, int fd);
int view_mail_inbox(int fd, int sid);
map<int, Mail> parse_mailbox(string res, int sid);



//create HTML pages
string create_mailinbox_html(string res);
string create_mail_html(Mail mail, string id);

// storage drive page
string drive_page(string current_path, unordered_map<string,string> configmap);
string format(string filename, string before, string after);


//others
void signal_handler(int signo);
bool do_read(int fd, char *buf, int len);
bool do_write(int fd, char *buf, int len);
bool do_read_ver2(int fd, char *buf, int pointer);
string char_to_str(char* a, int s, int e);
int connect_server(int port);
map<string, string> tokenize(string s);
bool do_read_ok_err(int fd, char* buf, int rlen);
string do_read_res(int fd, char* buf, int rlen);
int parse_cookie(string post_head, bool &has_cookie);
string replace_all(string str, const string& start, const string& end);

//reading packets
bool do_read(int fd, char *buf, int len) {
	int rcvd = 0;
	while (rcvd < len) {
		int n = read(fd, &buf[rcvd], len-rcvd);
		printf("Read %d bytes\n", n);
		if (n < 0) {
			return false;
		}
		rcvd += n;

		char *end = strstr(buf, "\r\n");
		if (end) {
			buf[rcvd] = '\0';
			return true;
		}
	}
	return true;
}

//writing packets
bool do_write(int fd, char *buf, int len) {
	int sent = 0;

	while (sent < len) {
		int n = write(fd, &buf[sent], len-sent);

		if (n < 0) {
			return false;
		}

		sent += n;

		char *end = strstr(buf, "\r\n");
		if (end) {
			buf[sent] = '\0';
			return true;
		}
	}
	return true;
}

bool do_read_ver2(int fd, char *buf, int pointer){
	// reading version 2 using pointers
	int rlen = 10000;
	while (true){
		int n = read(fd, &buf[pointer], rlen-pointer);
		if (n<0){
			return false;
		}
		return true;
	}
	return true;
}

string char_to_str(char* a, int s, int e) {
	string out = "";
	for (int i = s; i < e; ++i) {
		out = out + a[i];
	}
	return out;
}

void signal_handler(int signo){
	if (signo==SIGINT){
		for (int i=0; i<num_threads;i++){
			char shutdown[40] = "-ERR Shutting down server\r\n";
			do_write(fds[i], shutdown, strlen(shutdown));
			close(fds[i]);
		}
	}
	exit(0);
}

bool alphanumeric(string username){
	// returns true if username is valid (alphanumeric)
	auto i = find_if(username.begin(), username.end(), [](char const &c){
		return !isalnum(c);});
	return i == username.end();
}


string open_page(string path) {

    stringstream content;
    string fullpath = "./frontend/components" + path;
	ifstream ifs(fullpath);

    if (!ifs.is_open()){
        cerr<<"Cannot open file\n"<<endl;
        exit(1);
    }
    content<<ifs.rdbuf();

//    while (getline(ifs, str)){
//        content<<str;
//    }
    ifs.close();
    return content.str();
}

string open_page_with_edit(string path, string marker, string toInsert) {
    ifstream ifs;
	string str;
    stringstream content;
    string fullpath = "./frontend/components" + path;
	ifs.open(fullpath);

    if (!ifs.is_open()){
        cerr<<"Cannot open file\n"<<endl;
        exit(1);
    }
    while (getline(ifs, str)){
        content<<str;
        if (str.find(marker)!=string::npos) {
        	content<<toInsert;
        }
    }
    ifs.close();
    return content.str();
}

map<string, string> tokenize(string s) {
	string s1 = "&";
	string s2 = "=";
	map<string, string> query;

    int start = 0;
	int end = -1*s1.size();

   do {
        start = end + s1.size();
        end = s.find(s1, start);
		string pair = s.substr(start, end - start);
        int s2_pos = pair.find(s2); 
		string key = pair.substr(0, s2_pos); 
		string value = pair.substr(s2_pos + 1, strlen(pair.c_str()) - s2_pos);
		query[key] = value;

		cout << "key:" << key << "," << "value:" << value << endl;
    }  while (end != -1);

	return query;
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

void render_page(string content, int fd) {
	//if 200 OK
	string status = "HTTP/1.1 200 OK\r\n";
	string type = "Content-Type: text/html; charset=utf-8\r\n";
	string length = "Content-Length: " + to_string(content.size()) + "\r\n";

	string res_str  = status + type + length + "\r\n" + content + "\r\n";
	char res[res_str.length() + 1];
	strcpy(res, res_str.c_str());
	do_write(fd, res, strlen(res));
}


void render_next_page(string content, int fd, string pagename, string curr_path) {
	//if 200 OK
	string status = "HTTP/1.1 303 See Other\r\n";
	string type = "Content-Type: text/html; charset=utf-8\r\n";
	string length = "Content-Length: " + to_string(content.size()) + "\r\n";
	string location = "Location: " + pagename + curr_path + "\r\n";

	string res_str  = status + type + length + location + "\r\n" + content + "\r\n";
	char res[res_str.length() + 1];
	strcpy(res, res_str.c_str());
	do_write(fd, res, strlen(res));
}



void render_page_with_cookie(string content, int fd, string cookie, string pagename){
	// adds cookie information
	string status = "HTTP/1.1 303 See Other\r\n";
	string type = "Content-Type: text/html; charset=utf-8\r\n";
	string length = "Content_Length: " + to_string(content.size()) + "\r\n";
	string location = "Location: " + pagename + "\r\n";
	string res_str = status + type + length + location + cookie + "\r\n" + content + "\r\n";
	char res[res_str.length() + 1];
	strcpy(res, res_str.c_str());
	do_write(fd, res, strlen(res));
}


void render_page_content_type(string content, int fd, string contenttype) {
	//if 200 OK
	string status = "HTTP/1.1 200 OK\r\n";
	string type = "Content-Type: "+contenttype+"\r\n";
	string length = "Content-Length: " + to_string(content.size()) + "\r\n";
	//string location = "Location: /drive/lectures/image.png\r\n";

	string res_str  = status + type + length + "\r\n" + content + "\r\n";
	char res[res_str.length() + 1];
	strcpy(res, res_str.c_str());
	do_write(fd, res, strlen(res));
}
// return 1 if password matches, -1 if login failed
int check_login(string username, string password, int fd){

	password = replace_all(password, "%40", "@");
	password = replace_all(password, "%21", "!");
	password = replace_all(password, "%26", "&");
	password = replace_all(password, "%25", "%");
	password = replace_all(password, "%24", "$");
	password = replace_all(password, "%24", "#");
	SocketCommunicator sc_storage(storage_fd); // @suppress("Type cannot be resolved")
	bool getr = sc_storage.send_GET_request("users", username); // @suppress("Method cannot be resolved")
	vector<char> pwd = sc_storage.parse_GET_response(getr); // @suppress("Method cannot be resolved") // @suppress("Invalid arguments")

	string pass(pwd.begin(), pwd.end());
	cout<<"pwd: "<<pass<<endl;

	if (pass.compare(password)==0) {
		return 1;
	} else {
		return -1;
	}
}


int create_new_user(string username, string password, int fd){
	bool userExists = false;

	// check if user exists or not
	SocketCommunicator sc_storage(storage_fd); // @suppress("Type cannot be resolved")
	sc_storage.send_GET_request("users", username);
	sc_storage.parse_GET_response(userExists);

	if (userExists){
		// login already exists so cannot create a new user
		return -1;
	} else {
		cout << "here2" << endl;
		cout << password << endl;
		vector<char> p(password.begin(), password.end());
		bool putr = sc_storage.send_PUT_request("users", username, p);
		if (putr){
			bool success = sc_storage.parse_PUT_response();
			if (success){
				return 1;
			} else {
				return -1;
			}
		}
	}
	return -1;
}

int change_user(string username, string password, int fd) {
	bool userExists = false;

	// check if user exists or not
	SocketCommunicator sc_storage(storage_fd); // @suppress("Type cannot be resolved")
	sc_storage.send_GET_request("users", username);
	sc_storage.parse_GET_response(userExists);

	if (userExists){
		vector<char> p(password.begin(), password.end());
		bool putr = sc_storage.send_PUT_request("users", username, p);
		if (putr){
			bool success = sc_storage.parse_PUT_response();
			if (success){
				return 1;
			} else {
				return -1;
			}
		}
	}
	return -1;
}

int view_mail_inbox(int fd, int sid) {

	cout << "SID: " << sid << ", USER: " << cookies_dic[sid] << endl;

	int pop3fd = 0;
	int smtpfd = 0;

	char pop3_inbox_buf[1000];

	if (!initialized[sid]) {
		pop3fd = connect_server(POP3PORT);
		pop3_fds[sid] = pop3fd;
		bool authen = false;



		if (!do_read_ok_err(pop3fd, pop3_inbox_buf, 1000)) {
			fprintf(stderr, "connection to pop3 failed.\n");
			return -1;
		}

		if (vFlag) {
			printf("[%d] S: %s", fd, "connected to POP3 server\r\n");
		}


		string pop3_user = "USER " + cookies_dic[sid] + "\r\n";
		char pop3_user_char[pop3_user.length() + 1];
		strcpy(pop3_user_char, pop3_user.c_str());

		do_write(pop3fd, pop3_user_char, strlen(pop3_user_char));

		if (vFlag) {
			printf("[%d] S: %s", fd, pop3_user.c_str());
		}

		if (do_read_ok_err(pop3fd, pop3_inbox_buf, 1000)) {
			char pop3_pass_char[] = "PASS cis505\r\n";
			do_write(pop3fd, pop3_pass_char, strlen(pop3_pass_char));

			if (vFlag) {
				printf("[%d] S: %s", fd, pop3_pass_char);
			}

			if (!do_read_ok_err(pop3fd, pop3_inbox_buf, 1000)) {
				fprintf(stderr, "unable to connect to pop3: pass\n");
				return -1;
			}
		} else {
			fprintf(stderr, "unable to connect to pop3: user\n");
			return -1;
		}


		char smtp_buf[1000];
		memset(smtp_buf, 0, 1000);
		smtpfd = connect_server(SMTPPORT);
		smtp_fds[sid] = smtpfd;
		bool connected = false;



		if (!do_read_ok_err(smtpfd, smtp_buf, 1000)) {
			fprintf(stderr, "connection to smtp failed.\n");
			return -1;
		}

		if (vFlag) {
			printf("[%d] S: %s", fd, "connected to SMTP server\r\n");
		}

		char smtp_helo[] = "HELO localhost\r\n";

		do_write(smtpfd, smtp_helo, strlen(smtp_helo));

		if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
			connected = true;
		} else {
			fprintf(stderr, "unable to connect to smtp: hello\n");
			return -1;
		}
		initialized[sid] = true;
	} else {
		pop3fd = pop3_fds[sid];
		smtpfd = smtp_fds[sid];
	}

	cout << "POP3 FD:" << pop3fd << "," << "SMTP FD:" << smtpfd << endl;

//	if (authen) {
//		char temp[] = "DELE 1\r\n";
//		do_write(pop3fd, temp, strlen(temp));
//
//		char temp2[] = "DELE 2\r\n";
//		do_write(pop3fd, temp2, strlen(temp2));
//
//		char temp3[] = "QUIT\r\n";
//		do_write(pop3fd, temp3, strlen(temp3));

	char pop3_uidl_char[] = "UIDL\r\n";
	do_write(pop3fd, pop3_uidl_char, strlen(pop3_uidl_char));

	if (vFlag) {
		printf("[%d] S: %s", fd, pop3_uidl_char);
	}

	if (do_read_ok_err(pop3fd, pop3_inbox_buf, 1000)) {
		string uidl_res = do_read_res(pop3fd, pop3_inbox_buf, 1000);
		parse_mailbox(uidl_res, sid);

		string content = create_mailinbox_html(uidl_res);

		string mailinbox_html = "/mailinbox.html";
		string content_edited = open_page_with_edit(mailinbox_html, "</center>", content);
		render_page(content_edited, fd);
		return 1;
	} else {
		fprintf(stderr, "unable to get UIDL res\n");
		return 1;
	}
//	} else {
//		fprintf(stderr, "not authorized to do UIDL command\n");
//		return -1;
//	}
}




string replace_all(string str, const string& start, const string& end) {
	size_t from = 0;
	while ((from = str.find(start, from)) != string::npos) {
		str.replace(from, start.length(), end);
		from += end.length();
	}
	return str;
}

int send_mail(int fd, int sid, string content) {

	char smtp_buf[1000];
	memset(smtp_buf, 0, 1000);
	int smtpfd = smtp_fds[sid];
	bool connected = false;
	if (smtpfd > 0) {
		connected = true;
	}

	map<string, string> stmp_query = tokenize(content);

	string recipients = stmp_query["recipients"];
	recipients = replace_all(recipients, (string)"%40", (string)"@");
	string subject = stmp_query["subject"];
	subject = replace_all(subject, (string)"+", (string)" ");
	subject = replace_all(subject, (string)"%21", (string)"!");
	subject = replace_all(subject, (string)"%27", (string)"'");
	subject = replace_all(subject, (string)"%2c", (string)",");
	subject = replace_all(subject, (string)"%3f", (string)"?");

	string msg = stmp_query["message"];
	msg = replace_all(msg, (string)"+", (string)" ");
	msg = replace_all(msg, (string)"%21", (string)"!");
	msg = replace_all(msg, (string)"%27", (string)"'");
	msg = replace_all(msg, (string)"%2c", (string)",");
	msg = replace_all(msg, (string)"%3f", (string)"?");


	vector<string> names;
	int start = 0;
	for (int i = 0; i < strlen(recipients.c_str()) - 2; i++) {
		if (recipients[i] == '%' && recipients[i+1] == '3' && toupper(recipients[i+2]) == 'C') {
			start = i + 3;
		}
		if (recipients[i] == '%' && recipients[i+1] == '3' && toupper(recipients[i+2]) == 'E') {
			names.push_back(recipients.substr(start, i-start));
		}
	}

	if (connected) {
		string smtp_from = "MAIL FROM:<" + cookies_dic[sid] + "@localhost>\r\n";
		char smtp_from_char[smtp_from.length() + 1];
		strcpy(smtp_from_char, smtp_from.c_str());

		do_write(smtpfd, smtp_from_char, strlen(smtp_from_char));

		if (vFlag) {
			printf("[%d] S: %s", fd, smtp_from.c_str());
		}

		if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
			for (string each : names) {
				string smtp_to = "RCPT TO:<" + each + ">\r\n";
				char smtp_to_char[smtp_to.length() + 1];
				strcpy(smtp_to_char, smtp_to.c_str());

				do_write(smtpfd, smtp_to_char, strlen(smtp_to_char));

				if (vFlag) {
					printf("[%d] S: %s", fd, smtp_to.c_str());
				}

				if (!do_read_ok_err(smtpfd, smtp_buf, 1000)) {
					fprintf(stderr, "unable to complete RCPT TO command\r\n");
					return -1;
				}
			}
		} else {
			fprintf(stderr, "unable to get MAIL FROM res\n");
			return -1;
		}
		char smtp_data[] = "DATA\r\n";
		do_write(smtpfd, smtp_data, strlen(smtp_data));

		if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
			string subj = "Subject: (no subject)\r\n";

			if (stmp_query["subject"] != "") {
				subj = "Subject: " + subject + "\r\n";
			}
			string message = msg + "\r\n.\r\n";

			char smtp_msg[strlen(subj.c_str()) + strlen(message.c_str()) + 1];
			strcpy(smtp_msg, subj.c_str());
			strcat(smtp_msg, message.c_str());
			do_write(smtpfd, smtp_msg, strlen(smtp_msg));

			if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
				cout << "successful" << endl;
			}

			if (vFlag) {
				printf("[%d] S: %s", fd, smtp_msg);
			}
		}
		return 1;
	} else {
		fprintf(stderr, "not authorized to do MAIL command\n");
		return -1;
	}
}

bool do_read_ok_err(int fd, char* buf, int rlen) {
	char nbuf[1000];

	while (true) {
		memset(nbuf, 0, 1000);
		memset(buf, 0, 1000);
		bool res = do_read(fd, nbuf, rlen);
		strcat(buf, nbuf);

		cout << buf << "END" << endl;

		while (true) {
			char *end = strstr(buf, "\r\n");
			if (end) {
				int pos = end - buf + 2;
				if (strncasecmp(buf, "-ERR", 4) == 0) {
					strcpy(buf, buf + pos);
					return false;
				} else if (strncasecmp(buf, "+OK ", 4) == 0) {
					strcpy(buf, buf + pos);
					return true;
				} else if ((strncasecmp(buf, "220 localhost", 13) == 0) ||
						(strncasecmp(buf, "250 localhost", 13) == 0)) {
					strcpy(buf, buf + pos);
					return true;
				} else if (strncasecmp(buf, "250 OK", 6) == 0) {
					strcpy(buf, buf + pos);
					return true;
				} else if (strncasecmp(buf, "354 ", 4) == 0) {
					strcpy(buf, buf + pos);
					return true;
				}

			} else {
				break;
			}
		}
	}
}


string do_read_res(int fd, char* buf, int rlen) {

	string body = string(buf);
	size_t i = body.find("\r\n.\r\n");
	if (i != string::npos) {
		int pos = i;
		string res = char_to_str(buf, 0, pos);
		strcpy(buf, buf + pos);
		return res;
	} else {
		fprintf(stderr, "unable to read response\n");
		exit(1);
	}
}

string create_mailinbox_html(string res) {
	istringstream tokenStream(res);
	string token;
	char delimiter = '\n';

	string output = "<ul style=\"list-style: none;\">\r\n";
	while (getline(tokenStream, token, delimiter)) {
		int ws_index = token.find(" ");
		string id = token.substr(0, ws_index);
		output += "<li> <a href=\"/mail.html?id=" + id + "\">" + "Message " + id + "</a></li>";
	}
	output += "</ul>";
	return output;
}


map<int, Mail> parse_mailbox (string res, int sid) {
	istringstream tokenStream(res);
	string token;
	char delimiter = '\n';
	char pop3_mail_buf[1000];
	memset(pop3_mail_buf, 0, 1000);

	map<int, Mail> mail_dic;
	vector<string> mids;


	while (getline(tokenStream, token, delimiter)) {
		int ws_index = token.find(" ");
		string id = token.substr(0, ws_index);
		mids.push_back(id);
	}

	for (string each : mids) {

		int mid = stoi(each);

		string pop3_retr = "RETR " + each + "\r\n";
		char pop3_retr_char[pop3_retr.length() + 1];
		strcpy(pop3_retr_char, pop3_retr.c_str());

		int pop3_fd = pop3_fds[sid];
		do_write(pop3_fd, pop3_retr_char, strlen(pop3_retr_char));

		if (do_read_ok_err(pop3_fd, pop3_mail_buf, 1000)) {
			string retr_res = string(pop3_mail_buf);

			istringstream mail_stream(retr_res);
			string line;

			while (getline(mail_stream, line, delimiter)) {
				if (strncasecmp(line.c_str(), "From ", 5) == 0) {
					struct Mail mail;

					mail.id = each;
					size_t space = line.find("> ");
					mail.sender = line.substr(6, space - 6);
					mail.date = line.substr(space + 1);
					mail_dic[mid] = mail;


				} else if (strncasecmp(line.c_str(), "Subject:", 8) == 0) {
					mail_dic[mid].subject = line.substr(9);
				} else if (strncasecmp(line.c_str(), ".\r", 2) == 0) {
				} else if (strncasecmp(line.c_str(), "Content", 7) == 0) {
				} else {
					mail_dic[mid].msg += line + '\n';
				}
			}
		}



	}
	mailboxes[sid] = mail_dic;
	return mail_dic;
}

string create_mail_html(Mail mail, string mid) {
//	istringstream tokenStream(res);
//	string token;

	string output = "<center> <p id=\"mid\">" + mid + "</p><br><a href=\"/mailinbox.html\">Back</a></center>\r\n";
	output += "<p id=\"sender\">Sender:" + mail.sender + "</p>\r\n";
	output += "<p id=\"date\">Date:" + mail.date + "</p>\r\n";
	output += "<p id=\"subject\">Subject:" + mail.subject + "</p>\r\n\r\n";
	output += "<p id=\"body\">" + mail.msg + "</p>\r\n";
	output += "<div style=\"float:left;\">";
	output += "<p>Reply:</p><form action=\"/replyEmail\" method=\"post\"><div class=\"container\"><input type=\"hidden\" name=\"id\" value=\"" + mid +"\"><br>\r\n";
	output += "<textarea type=\"text\" placeholder=\"reply here\" name=\"message\" size=\"40\" height=\"400\" width=\"800\"></textarea>";
	output += "<button type=\"submit\">Send</button></div></form>";

	output += "<p>Forward:</p><form action=\"/forwardEmail\" method=\"post\"><div class=\"container\"><input type=\"hidden\" name=\"id\" value=\"" + mid +"\"><br>\r\n";
	output += "<input type=\"text\" placeholder=\"Forward to <foo@localhost> \" name=\"rcpt\" size=\"30\">";
	output += "<button type=\"submit\">Send</button></div></form>";

	output += "<br><form action=\"/deleteEmail\" method=\"post\"><div class=\"container\"><input type=\"hidden\" name=\"id\" value=\"" + mid +"\"><br>\r\n";
	output += "<button type=\"submit\">Delete</button></div></form></div>";
	return output;
}

void post_handler(char *nbuf, int fd) {
	/*HTTP/2.0 200 OK
	Content-Type: text/html
	Set-Cookie: username=cis505
	Set-Cookie: password=final*/
	char *space = strstr(nbuf, " ");
	int space_pos = space - nbuf;
	string path = char_to_str(nbuf, 0, space_pos);
	cout<<"in register\n"<<endl;
	cout<<"path: "<<path<<endl;
	cout<<"nbuf: "<<nbuf<<endl;
	string contents(nbuf);
}

/*************************************************\
 *		Storage Drive Functions
 *
 ***************************************************/
string format(string filename, string before, string after){
	int s = 0;
	while ((s=filename.find(before, s)) != string::npos){
		filename.replace(s, before.length(), after);
		s += after.length();
	}
	return filename;
}

string drive_page(string current_path, unordered_map<string, string> configmap){
	string drive;
	cout<<"in drive page"<<endl;
	drive+="<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>Storage Drive</title></head>";
	drive += "<body>";
	drive+="<center> <h1> My Drive</h1></center><br><br>";
	drive+="<b>Current: ./drive";

	drive+=current_path;
	drive+="</b><br><br>";

	cout<<"current path="<<current_path<<endl;
	vector<string> folders;
	vector<string> files;
	for (auto& i: configmap){
		string name = i.first;
		cout<<name<<endl;
		string t = name.substr(0, name.find_last_of('/')+1);
		cout<<t<<endl;
		if (name.substr(0, name.find_last_of('/')+1) == current_path || name.substr(0, name.find_last_of('/')) == current_path){
			if (i.second == "X" && name != current_path){
				folders.push_back(i.first);
			} else if (name!=current_path){
				cout<<i.first<<endl;
				files.push_back(i.first);
			}
		}
	}

	string paths_to_move_to_folder = "";
	for (int i = 0; i<folders.size();i++){
		paths_to_move_to_folder += "<option value=\"";
		paths_to_move_to_folder += folders[i];
		paths_to_move_to_folder += "\">";
		paths_to_move_to_folder += folders[i];
		paths_to_move_to_folder += "</option>";
	}

	string paths_to_move_to_file = "";
	for (int i = 0; i<folders.size();i++){
		paths_to_move_to_file += "<option value=\"";
		paths_to_move_to_file += folders[i];
		paths_to_move_to_file += "\">";
		paths_to_move_to_file += folders[i];
		paths_to_move_to_file += "</option>";
	}

//	// have to display folders
	drive += "<b>Folders:</b><br>";
	drive+="<table><tr><th>Name</th><th>Rename</th><th>Move To</th><th>Delete</th>";
	for (int i=0; i<folders.size();i++){
		drive+="<tr><td><form action=\"/openfolder\" method=\"POST\">";
		drive+="<button name=\"";
		drive+=folders[i];
		drive+="\">";
		drive+= folders[i].substr(folders[i].find_last_of("/")+1);
		drive+="</button></form></td></tr>";
		drive+="<td><form action=\"/renamefolder\" method=\"POST\"><input type=\"text\" name=\"";
		drive+=folders[i];
		drive+="\" placeholder=\"new name\" required><input type=\"submit\" value=\"Rename\"></form></td>";

		drive+="<td><form action=\"/movefolder\" method=\"POST\"><select name=\"";
		drive+=folders[i];
		drive+="\">";
		// add all posible paths to choose from
		drive+=paths_to_move_to_folder;
		drive+="</select><input type=\"submit\" value=\"move\"></form></td>";

		drive+= "<td><form action=\"/deletefolder\" method=\"POST\">";
		drive+="<button name=\"delete\" value=\"";
		drive+=folders[i];
		drive+="\">delete</button></form></td></tr>";
	}
	drive+="</table><br>";

	// Add new folder
	drive+= "<br><p>Add a new folder</p>";
	drive+="<form action=\"/newfolder\" method=\"POST\">";
	drive+="<input type=\"text\" name=\"foldername\" placeholder=\"folder name\" required>";
	drive+="<input type=\"submit\" value=\"submit\"><br></form><br>";

	drive += "<b>Files:</b><br>";
	drive+="<table><tr><th>Name</th><th>Rename</th><th>Move To</th><th>Delete</th>";
	for (int i=0; i<files.size();i++){
		// download
		drive+="<tr><td>";
		drive+="<a href=\"";
		drive+= files[i];
		drive+="\">";
		drive+= files[i].substr(files[i].find_last_of("/")+1);
		drive+="</a></td>";

		// rename file
		drive+="<td><form action=\"/renamefile\" method=\"POST\"><input type=\"text\" name=\"";
		drive+=files[i];
		drive+="\" placeholder=\"new name\" required><input type=\"submit\" value=\"Rename\"></form></td>";

		//move file
		drive+="<td><form action=\"/movefile\" method=\"POST\"><select name=\"";
		drive+=files[i];
		drive+="\">";
		// add all possible paths to choose from
		drive+=paths_to_move_to_file;
		drive+="</select><input type=\"submit\" value=\"move\"></form></td>";

		// delete button
		drive+="<td><form action=\"/deletefile\" method=\"POST\">";
		drive+="<button name=\"delete\" value=\"";
		drive+=files[i];
		drive+="\">delete</button></form></td></tr>";
	}
	drive+="</table>";
	// upload file button
	drive+= "<br><p>Add a new file</p>";
	drive+="<form action=\"/newfile\" enctype=\"multipart/form-data\" method=\"POST\">";
    drive+="<input type=\"file\" name=\"filename\" required>";
    drive+="<input type=\"submit\" value=\"upload\"><br></form><br>";

    drive+="<a href=\"/home.html\">Back To Home</a><br>";
    drive+="<a href=\"/\">Log Out</a>";
	drive+="</body></html>";

	return drive;
}


void *worker(void *arg){
	int comm_fd = *(int*)arg;
	string command;

	int rlen = 100000;
	char *buf = new char[rlen];
	bzero(buf, sizeof(buf));
	int pointer = 0;

	char post_header[10000];
	bzero(post_header, sizeof(post_header));
	memset(post_header, 0, 10000);
	char post_command[40];
	memset(post_command, 0, 40);

	char get_messages[1000];
	memset(get_messages, 0, 500);

	char get_header[1000];
	bzero(get_header, sizeof(get_header));
	memset(get_header, 0, 1000);
	char get_command[40];
	memset(get_command, 0, 40);

	char url[60];
	memset(url, 0, 60);
	char HTTPv[30];
	memset(HTTPv, 0, 30);



	string current_path = "";
	string current_user = "";

	unordered_map<string,string> configmap;

	bool get = false;
	bool post = false;
	bool head = false;
	//bool logged_in = false;
	bool post_info = false;
	bool has_cookie;
	bool in_drive = false;

	int cookie_id = rand();

	while (true){
		signal(SIGINT, signal_handler);
		bool res = do_read_ver2(comm_fd, buf, pointer);

		while (strstr(buf,"\n")) {
			pointer += strlen(buf);
			int current_size = 0;
			for (int i = 0; i<strlen(buf); i++){
				current_size += 1;
				if (buf[i] == '\n'){
					char *line = new char[12000];
					bzero(line, sizeof(line));
					strncpy(line, buf, current_size);

					//cout<<"buffer: "<<line<<endl;
					// parse possible commands POST, GET, HEAD\
					// POST or HEAD
					char comm_4[5];
					strncpy(comm_4, line, 4);
					comm_4[4] = '\0';

					// GET
					char comm_3[4];
					strncpy(comm_3, line, 3);
					comm_3[3] = '\0';



					if (post){
						strcat(post_header, line);
						//cout<<post_header<<endl;
						// add to the post_header until content-length line
						if (strlen(line)<=2 &&
							strstr(line, "\r\n")&&
							(string(post_header).find("Content-Length:")!=string::npos)){

						//	cout << "<post>" << string(post_header).find("Cookie:") << endl;

							string post_head = string(post_header);
							bool has_cookie;
							int cookie_out = parse_cookie(post_head, has_cookie);

							if (has_cookie) {
								current_user = cookies_dic[cookie_out];
								logged_in[cookie_out] = true;
							} else {
								logged_in[cookie_out] = false;
							}

							char post_message[300];
							memset(post_message, 0, 300);
							strcpy(post_message,buf);
							string post_m = string(post_message).substr(2); // \r\n
							cout<<"post size: "<<sizeof(post_m)<<endl;
							current_size += 300;



							bool success;
							SocketCommunicator sc_storage(storage_fd);
							configmap = sc_storage.configToMap(current_user, success);

							if (strcmp(post_command, "/login.html")==0){
								map<string, string> query = tokenize(post_m);
								if (alphanumeric(query["username"])){
									int login_successful = check_login(query["username"], query["password"], comm_fd);

									if (login_successful == 1){
										// set cookie
										current_user = query["username"];
										string cookie1 = "Set-Cookie: username="+ current_user+"\r\n";
										string cookie2 = "Set-Cookie: sid="+ to_string(cookie_id)+"\r\n";
										string cookie = cookie1+cookie2;

										logged_in[cookie_id] = true;

										cookies_dic[cookie_id]= query["username"];

										cout << "whats put" << cookie_id << "," << cookies_dic[cookie_id] << endl;
										string content = open_page("/home.html");
										render_page_with_cookie(content, comm_fd, cookie, "/home.html");
//									} else if (login_successful == 1) {
//										logged_in[cookie_out] = true;
//
//										cookies_dic[cookie_out] = query["username"];
//
//										string content= open_page("/home.html");
//										render_page(content, comm_fd);
////										string content = open_page("/home.html");
////										render_page(content, comm_fd);
//									}
									} else {
										string content = open_page("/loginfailed.html");
										render_page(content, comm_fd);
									}
								}else {
									string content = open_page("/loginfailed.html");
									render_page(content, comm_fd);
								}
							} else if (strcmp(post_command, "/registration.html")==0){
								// username, password
								map<string, string> query = tokenize(post_m);
								if (alphanumeric(query["username"])){
									// check if the user exists
									string password = query["password"];
									password = replace_all(password, "%40", "@");
									password = replace_all(password, "%21", "!");
									password = replace_all(password, "%26", "&");
									password = replace_all(password, "%25", "%");
									password = replace_all(password, "%24", "$");
									password = replace_all(password, "%24", "#");
									int registered = create_new_user(query["username"], password, comm_fd);

									if (registered == 1){
										string content = open_page("/login.html");
										cout<<"im here heh"<<endl;
										render_page(content, comm_fd);
									} else {
										string content = open_page("/registrationFailed.html");
										render_page(content, comm_fd);
									}
								}
							} else if (strcmp(post_command, "/resetUser")==0) {
								map<string, string> query = tokenize(post_m);
								if (alphanumeric(query["username"])){
									// check if the user exists
									string password = query["new_password"];
									password = replace_all(password, "%40", "@");
									password = replace_all(password, "%21", "!");
									password = replace_all(password, "%26", "&");
									password = replace_all(password, "%25", "%");
									password = replace_all(password, "%24", "$");
									password = replace_all(password, "%24", "#");
									int registered = change_user(query["username"], password, comm_fd);
									if (registered == 1){
										string content = open_page("/login.html");
										render_page(content, comm_fd);
									} else {
										string content = open_page("/changePasswordFailed.html");
										render_page(content, comm_fd);
									}
								}
							} else if (strcmp(post_command, "/sendEmail") == 0) {
								if (logged_in[cookie_out]) {
									if (send_mail(comm_fd, cookie_out, post_m) == 1) {
										string content = open_page("/mailsuccess.html");
										render_page(content, comm_fd);
									} else {
										string content = open_page("/error.html");
										render_page(content, comm_fd);
									}
								} else {
										string content = open_page("/login.html");
										render_page(content, comm_fd);
									}
							} else if (strcmp(post_command, "/replyEmail") == 0) {
								if (logged_in[cookie_out]) {

									char smtp_buf[1000];
									memset(smtp_buf, 0, 1000);
									map<string, string> query = tokenize(post_m);
									string mid_str = query["id"];
									string new_msg = query["message"];
									new_msg = replace_all(new_msg, (string)"+", (string)" ");
									new_msg = replace_all(new_msg, (string)"%21", (string)"!");
									new_msg = replace_all(new_msg, (string)"%27", (string)"'");
									new_msg = replace_all(new_msg, (string)"%2c", (string)",");
									new_msg = replace_all(new_msg, (string)"%3f", (string)"?");

									int mid = stoi(mid_str.c_str());
									Mail original = mailboxes[cookie_out][mid];

									string sender = original.sender;
									string subject = original.subject;
									string old_msg = original.msg;

									int smtpfd = smtp_fds[cookie_out];


									string smtp_from = "MAIL FROM:<" + cookies_dic[cookie_out] + "@localhost>\r\n";
									char smtp_from_char[smtp_from.length() + 1];
									strcpy(smtp_from_char, smtp_from.c_str());

									do_write(smtpfd, smtp_from_char, strlen(smtp_from_char));

									if (vFlag) {
										printf("[%d] S: %s", comm_fd, smtp_from.c_str());
									}

									if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
										string rcpt_str = "RCPT TO:<" + sender + ">\r\n";
										char rcpt_char[rcpt_str.length() + 1];
										strcpy(rcpt_char, rcpt_str.c_str());
										do_write(smtpfd, rcpt_char, strlen(rcpt_char));

										if (vFlag) {
											printf("[%d] S: %s", comm_fd, rcpt_char);
										}

										if (!do_read_ok_err(smtpfd, smtp_buf, 1000)) {
											fprintf(stderr, "unable to complete RCPT TO command\r\n");
										}
									} else {
										fprintf(stderr, "unable to get MAIL FROM res\n");
									}
									char smtp_data[] = "DATA\r\n";
									do_write(smtpfd, smtp_data, strlen(smtp_data));

									if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
										string subj = "Subject: (reply)" + subject + "\r\n";
										string message = new_msg + "\n\n" + "Replying to:" + old_msg + ".\r\n";
										cout << message << endl;

										char smtp_msg[strlen(subj.c_str()) + strlen(message.c_str()) + 1];
										strcpy(smtp_msg, subj.c_str());
										strcat(smtp_msg, message.c_str());
										do_write(smtpfd, smtp_msg, strlen(smtp_msg));

										if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
											string content = open_page("/mailsuccess.html");
											render_page(content, comm_fd);
										}

										if (vFlag) {
											printf("[%d] S: %s", comm_fd, smtp_msg);
										}
									}
								} else {
									string content = open_page("/login.html");
									render_page(content, comm_fd);
								}
							} else if (strcmp(post_command, "/forwardEmail") == 0) {
								if (logged_in[cookie_out]) {
									char smtp_buf[1000];
									memset(smtp_buf, 0, 1000);
									map<string, string> frd_query = tokenize(post_m);
									string mid_str = frd_query["id"];
									string new_rcpt = frd_query["rcpt"];

									new_rcpt = replace_all(new_rcpt, (string)"%3C", (string)"<");
									new_rcpt = replace_all(new_rcpt, (string)"%40", (string)"@");
									new_rcpt = replace_all(new_rcpt, (string)"%3E", (string)">");

									int mid = stoi(mid_str.c_str());
									Mail original = mailboxes[cookie_out][mid];
									string sender = original.sender;
									string subject = original.subject;
									string old_msg = original.msg;

									int smtpfd = smtp_fds[cookie_out];


									string smtp_from = "MAIL FROM:<" + cookies_dic[cookie_out] + "@localhost>\r\n";
									char smtp_from_char[smtp_from.length() + 1];
									strcpy(smtp_from_char, smtp_from.c_str());

									do_write(smtpfd, smtp_from_char, strlen(smtp_from_char));

									if (vFlag) {
										printf("[%d] S: %s", comm_fd, smtp_from.c_str());
									}

									if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
										string rcpt_str = "RCPT TO:" + new_rcpt + "\r\n";
										char rcpt_char[rcpt_str.length() + 1];
										strcpy(rcpt_char, rcpt_str.c_str());
										do_write(smtpfd, rcpt_char, strlen(rcpt_char));

										if (vFlag) {
											printf("[%d] S: %s", comm_fd, rcpt_char);
										}

										if (!do_read_ok_err(smtpfd, smtp_buf, 1000)) {
											fprintf(stderr, "unable to complete RCPT TO command\r\n");
										}
									} else {
										fprintf(stderr, "unable to get MAIL FROM res\n");
									}
									char smtp_data[] = "DATA\r\n";
									do_write(smtpfd, smtp_data, strlen(smtp_data));

									if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
										string subj = "Subject: (forward)" + subject + "\r\n";
										string message = old_msg + ".\r\n";

										char smtp_msg[strlen(subj.c_str()) + strlen(message.c_str()) + 1];
										strcpy(smtp_msg, subj.c_str());
										strcat(smtp_msg, message.c_str());
										do_write(smtpfd, smtp_msg, strlen(smtp_msg));

										if (do_read_ok_err(smtpfd, smtp_buf, 1000)) {
											string content = open_page("/mailsuccess.html");
											render_page(content, comm_fd);
										}

										if (vFlag) {
											printf("[%d] S: %s", comm_fd, smtp_msg);
										}
									}
								} else {
									string content = open_page("/login.html");
									render_page(content, comm_fd);
								}
							} else if (strcmp(post_command, "/newfile")==0){ // *
								cout<<"entered newfile"<<endl;
								string post_messages = post_header + post_m;
								cout<<post_messages<<endl;

								bool success;
								SocketCommunicator sc_storage(storage_fd);
								size_t filestart = post_messages.find("filename=\"")+10;
								size_t fileend = post_messages.find("Content-Type",filestart)-1;
								size_t start = post_messages.find("Content-Type", fileend);
								size_t mid = post_messages.find("\n",start)+2;
								size_t end = post_messages.find("----------",mid);
								current_path = current_paths[current_user];
								string filename;
								if (current_path.compare("/")==0){
									filename = current_path+post_messages.substr(filestart,fileend-filestart-2);
								} else{
									filename = current_path+"/"+post_messages.substr(filestart,fileend-filestart-2);
								}

								string filecontent = post_messages.substr(mid+1, end-mid-1);
								vector<char> file(filecontent.begin(), filecontent.end());
								success = sc_storage.uploadFile(configmap, current_user, filename, file);
								if (success){
									cout<<"successfully stored"<<endl;
									//configmap = sc_storage.configToMap(current_user, success);
									string content = open_page("/uploadsuccess.html");
									render_page(content, comm_fd);
								}
							} else if (strcmp(post_command, "/newfolder")==0){ //*
								// have to make sure folder ends with /
								map<string, string> parsed = tokenize(post_m);
								string foldername = parsed["foldername"];
								cout<<"folder name: "<<foldername<<endl;
								current_path = current_paths[current_user];
								string folderpath;
								if (current_path.compare("/")==0){
									folderpath = current_path+foldername;
								} else{
									folderpath = current_path+"/"+foldername;
								}
								cout<<"folder path: "<<folderpath<<endl;
								SocketCommunicator sc_storage(storage_fd);
								bool success = sc_storage.createFolder(configmap, folderpath, current_user);
								if (success){
									configmap = sc_storage.configToMap(current_user, success);
									string content = drive_page(current_path, configmap);
									render_next_page(content, comm_fd, "/drive", current_path);
								}
							} else if (strcmp(post_command, "/renamefile")==0){ //*
								current_path = current_paths[current_user];
								string old = post_m.substr(0, post_m.find("="));
								string newname = post_m.substr(post_m.find("=")+1);
								old = format(old, "%2F", "/");
								SocketCommunicator sc_storage(storage_fd);
								cout<<"newname: "<<newname<<endl;
								cout<<old<<endl;
								bool success = sc_storage.rename_file(old, newname, configmap, current_user);
								if (success){
									configmap = sc_storage.configToMap(current_user, success);
									string content = drive_page(current_path, configmap);
									render_next_page(content, comm_fd, "/drive", current_path);
								}
							} else if (strcmp(post_command, "/renamefolder")==0){ //*
								//cout<<post_m<<endl;
								current_path = current_paths[current_user];
								string old = post_m.substr(0, post_m.find("="));
								string newname = post_m.substr(post_m.find("=")+1);
								old = format(old, "%2F", "/");
								cout<<"old:"<<old<<endl;
								SocketCommunicator sc_storage(storage_fd);
								cout<<current_path+old<<endl;
								bool success = sc_storage.rename_folder(current_path.substr(0,current_path.length()-1)+old, newname, configmap, current_user);
								if (success){
									configmap = sc_storage.configToMap(current_user, success);
									string content = drive_page(current_path, configmap);
									render_next_page(content, comm_fd, "/drive", current_path);
								}
							} else if (strcmp(post_command, "/movefile")==0) {
								//cout<<post_m<<endl;
								current_path = current_paths[current_user];
								string oldpath = post_m.substr(0, post_m.find("="));
								string newpath = post_m.substr(post_m.find("=")+1);
								oldpath = format(oldpath, "%2F", "/");
								newpath = format(newpath, "%2F", "/");
								cout<<newpath<<endl;
								newpath = newpath+"/";
								cout<<oldpath<<endl;
								cout<<"new:"<<newpath<<endl;
								SocketCommunicator sc_storage(storage_fd);
								cout<<current_path+oldpath<<endl;
								bool success = sc_storage.move_file(oldpath, newpath, configmap, current_user);
								if (success){
									configmap = sc_storage.configToMap(current_user, success);
									string content = drive_page(current_path, configmap);
									render_next_page(content, comm_fd, "/drive", current_path);
								}
							} else if (strcmp(post_command, "/movefolder")==0) {
								//cout<<post_m<<endl;
								current_path = current_paths[current_user];
								string oldpath = post_m.substr(0, post_m.find("="));
								string newpath = post_m.substr(post_m.find("=")+1);
								oldpath = format(oldpath, "%2F", "/");
								newpath = format(newpath, "%2F", "/");
								newpath = current_path.substr(0,current_path.length())+newpath;
								cout<<oldpath<<endl;
								cout<<"new:"<<newpath<<endl;
								SocketCommunicator sc_storage(storage_fd);
								cout<<current_path+oldpath<<endl;
								bool success = sc_storage.move_folder(current_path+oldpath, newpath, configmap, current_user);
								if (success){
									configmap = sc_storage.configToMap(current_user, success);
									string content = drive_page(current_path, configmap);
									render_next_page(content, comm_fd, "/drive", current_path);
								}
							} else if (strcmp(post_command, "/deletefolder")==0){
								current_path = current_paths[current_user];
								map<string, string> parsed = tokenize(post_m);
								string foldername = parsed["delete"];
								cout<<"filename: "<<foldername<<endl;
								foldername = format(foldername, "%2F", "/");
								foldername = format(foldername, "%3A", ":");
								string folderpath;
								if (current_path.compare("/")==0){
									folderpath = foldername;
								} else{
									folderpath = current_path+"/"+foldername;
								}
								//string folderpath = current_path.substr(0,current_path.length()-1)+foldername;
								SocketCommunicator sc_storage(storage_fd);
								bool success;
								cout<<"current user:"<<current_user<<endl;
								cout<<"filepath: "<<folderpath<<endl;
								success = sc_storage.deleteFolder(configmap, folderpath, current_user);
								if (success){
									configmap = sc_storage.configToMap(current_user, success);
									string content = drive_page(current_path, configmap);
									render_next_page(content, comm_fd, "/drive", current_path);
								}
							} else if (strcmp(post_command, "/deletefile")==0){
								current_path = current_paths[current_user];
								map<string, string> parsed = tokenize(post_m);
								string filename = parsed["delete"];
								cout<<"filename: "<<filename<<endl;
								filename = format(filename, "%2F", "/");
								filename = format(filename, "%3A", ":");
								string filepath=filename;
								//string filepath = current_path.substr(0,current_path.length()-1)+filename;
								SocketCommunicator sc_storage(storage_fd);
								bool success;
								cout<<"current user:"<<current_user<<endl;
								cout<<"filepath: "<<filepath<<endl;
								success = sc_storage.deleteFile(configmap, current_user, filepath);
								if (success){
									configmap = sc_storage.configToMap(current_user, success);
									string content = drive_page(current_path, configmap);
									render_next_page(content, comm_fd, "/drive", current_path);
								}
							} else if (strcmp(post_command, "/openfolder")==0){
								int folder_index = post_m.find("=");
								string folder_to_open = post_m.substr(0,folder_index);
								folder_to_open = format(folder_to_open, "%2F", "/");
								current_path = folder_to_open;
								cout<<"folder opening: "<<current_path<<endl;
								current_paths[current_user] = current_path;
								SocketCommunicator sc_storage(storage_fd);
								bool success;
								configmap = sc_storage.configToMap(current_user, success);
								cout<<"current path: "<<current_path<<endl;
								cout<<"current user: "<<current_user<<endl;
								string content = drive_page(current_path, configmap);
								// render_page(content, comm_fd);
								render_next_page(content, comm_fd, "/drive", current_path);
								// open folder and doing functions within the file doesn't work
							} else if (strcmp(post_command, "/download")==0){
								current_path = current_paths[current_user];
								int file_index = post_m.find("=");
								string file_to_download = post_m.substr(0, file_index);
								file_to_download = format(file_to_download, "%2F", "/");
								cout<<"to download:"<<file_to_download<<endl;

								// file_to_download = current_path.substr(0,current_path.length()-1) + file_to_download;
								SocketCommunicator sc_storage(storage_fd);
								bool success;
								configmap = sc_storage.configToMap(current_user, success);
								string fileHash = configmap[file_to_download];
								vector<char> downloaded = sc_storage.downloadFile(current_user, fileHash, success);
								char *downloadingfile = &downloaded[0];
								string contenttype = "image/png; charset=utf-8";
								render_page_content_type(string(downloadingfile), comm_fd, contenttype);
							} else if (strcmp(post_command, "/drive")==0){
								string post_messages = post_header + post_m;
								// show drive main page
								current_path = '/';
								cout<<current_path<<endl;
								current_paths[current_user] = current_path;
								cout<<"in drive\n"<<endl;
								SocketCommunicator sc_storage(storage_fd);
								bool success;
								current_user = cookies_dic[cookie_out];
								cout<<"current user:"<<current_user<<endl;
								//configmap = sc_storage.configToMap(current_user, success);
								string content = drive_page(current_path, configmap);
								render_page(content, comm_fd);
							} else if (strcmp(post_command, "/deleteEmail") == 0) {
								cout << post_m << endl;
								if (logged_in[cookie_out]) {

									bool ready_reconnect = false;
									char pop3_buf[1000];
									memset(pop3_buf, 0, 1000);
									map<string, string> frd_query = tokenize(post_m);
									string mid_str = frd_query["id"];

									string pop3_dele = "DELE " + mid_str + "\r\n";
									char pop3_dele_char[pop3_dele.length() + 1];
									strcpy(pop3_dele_char, pop3_dele.c_str());

									int pop3fd = pop3_fds[cookie_out];

									do_write(pop3fd, pop3_dele_char, strlen(pop3_dele_char));

									if (vFlag) {
										printf("[%d] S: %s", comm_fd, pop3_dele_char);
									}

									if (do_read_ok_err(pop3fd, pop3_buf, 1000)) {
										string content = open_page("/deletesuccess.html");

										char pop3_quit[] = "QUIT\r\n";
										do_write(pop3fd, pop3_quit, strlen(pop3_quit));

										if (do_read_ok_err(pop3fd, pop3_buf, 1000)) {
											ready_reconnect = true;
										}
									}
									//QUIT and Reconnect
									if (ready_reconnect) {
										int new_pop3fd = connect_server(POP3PORT);
										pop3_fds[cookie_out] = new_pop3fd;
										bool authen = false;



										if (!do_read_ok_err(new_pop3fd, pop3_buf, 1000)) {
											fprintf(stderr, "connection to pop3 failed.\n");
										}

										if (vFlag) {
											printf("[%d] S: %s", comm_fd, "connected to POP3 server\r\n");
										}


										string pop3_user = "USER " + cookies_dic[cookie_out] + "\r\n";
										char pop3_user_char[pop3_user.length() + 1];
										strcpy(pop3_user_char, pop3_user.c_str());

										do_write(new_pop3fd, pop3_user_char, strlen(pop3_user_char));

										if (vFlag) {
											printf("[%d] S: %s", comm_fd, pop3_user.c_str());
										}

										if (do_read_ok_err(new_pop3fd, pop3_buf, 1000)) {
											char pop3_pass_char[] = "PASS cis505\r\n";
											do_write(new_pop3fd, pop3_pass_char, strlen(pop3_pass_char));

											if (vFlag) {
												printf("[%d] S: %s", comm_fd, pop3_pass_char);
											}

											if (!do_read_ok_err(new_pop3fd, pop3_buf, 1000)) {
												fprintf(stderr, "unable to connect to pop3: pass\n");
											}
										} else {
											fprintf(stderr, "unable to connect to pop3: user\n");
										}
										string content = open_page("/deletesuccess.html");
										render_page(content, comm_fd);
									} else {
										fprintf(stderr, "DELETE not completed\r\n");
									}

								} else {
									string content = open_page("/login.html");
									render_page(content, comm_fd);
								}
							}
							post = false;

						}
					} else if (get) {
						strcat(get_header, line);

						// add to the post_header until content-length line
						if (strlen(line)<=2 &&
							strstr(line, "\r\n")){

							string get_head = string(get_header);

							bool has_cookie;
							int cookie_out = parse_cookie(get_head, has_cookie);

							string s(get_command);

							cout << "COOKIE: " << cookie_out << endl;
							if ((strcmp(get_command, "/") == 0) or (strcmp(get_command, "/login") == 0)) {
								string content = open_page("/login.html");
								render_page(content, comm_fd);
							} else if ((strcmp(get_command, "/loginfailed.html") == 0)) {
								string content = open_page("/loginfailed.html");
								render_page(content, comm_fd);
							} else if (strcmp(get_command, "/home.html") == 0) {
								if (logged_in[cookie_out]) {
									string content = open_page("/home.html");
									render_page(content, comm_fd);
								} else {
									string content = open_page("/login.html");
									render_page(content, comm_fd);
								}
							} else if (strcmp(get_command, "/registration") == 0) {
								string content = open_page("/registration.html");
								render_page(content, comm_fd);
							} else if (strcmp(get_command, "/changePassword") == 0) {
								string content = open_page("/changePassword.html");
								render_page(content, comm_fd);
							} else if (strcmp(get_command, "/mailinbox.html") == 0) {
								if (logged_in[cookie_out]) {
									if (view_mail_inbox(comm_fd, cookie_out) == -1) {
										string content = open_page("/error.html");
										render_page(content, comm_fd);
									}
								} else {
									string content = open_page("/login.html");
									render_page(content, comm_fd);
								}
							} else if (strstr(get_command, "/mail.html?")) {
								if (logged_in[cookie_out]) {
									string get_command_str = string(get_command);
									int ques_pos = get_command_str.find("?");
									map<string, string> query = tokenize(get_command_str.substr(ques_pos + 1));
									int mid = stoi(query["id"].c_str());

									map<int, Mail> mails = mailboxes[cookie_out];


									string content = create_mail_html(mails[mid], query["id"]);
									string mail_html = "/mail.html";
									string content_edited = open_page_with_edit(mail_html, "<body>", content);
									render_page(content_edited, comm_fd);
								} else {
									string content = open_page("/login.html");
									render_page(content, comm_fd);
								}
							} else if (strcmp(get_command, "/newemail.html?") == 0) {
								if (logged_in[cookie_out]) {
									string content = open_page("/newemail.html");
									render_page(content, comm_fd);
								} else {
									string content = open_page("/login.html");
									render_page(content, comm_fd);
								}
							} else if (strcmp(get_command, "/admin") == 0) {
								cout << "admin" << endl;
								//create_admin_console(int sid);
								string content = open_page("/admin.html");
								render_page(content, comm_fd);
							} else if (strcmp(get_command, "/getData") == 0) {
								//create_admin_console(int sid);
								SocketCommunicator sc_data(storage_fd);
								sc_data.send_GET_request("bigtable", "json");
								bool success;
								vector<char> data = sc_data.parse_GET_response(success);
								string content = "";
								for (auto i : data) {
								content += i;
								}
								//string content = open_page("/data.html");
								render_page(content, comm_fd);
							} else if (s.find(".png")!=string::npos){
								// render page with different content type
								cout<<"here"<<endl;
								cout<<get_command<<endl;
								string s(get_command);
								cout<<s<<endl;
								//s = s.substr(s.find("?")+1);
								//s = format(s, "%2F", "/");
								//s = format(s, "=", "");
								current_user = cookies_dic[cookie_out];
								SocketCommunicator sc_storage(storage_fd);
								bool success;
								configmap = sc_storage.configToMap(current_user, success);
								string fileHash = configmap[get_command];
								cout<<"file: "<<configmap[get_command]<<endl;
								vector<char> downloaded = sc_storage.downloadFile(current_user, fileHash, success);
								char *downloadingfile = &downloaded[0];
								string contenttype = "image/png; charset=utf-8";
								string content = string(downloadingfile);
								render_page_content_type(content, comm_fd, contenttype);
							}else if (strncasecmp(get_command, "/drive", 6)==0){
								cout<<"get command:"<<get_command<<endl;
								string s(get_command);
								current_user = cookies_dic[cookie_out];
								cout<<"current user:"<<current_user<<endl;
								cout<<"debugging:"<<s.substr(6)<<endl;
								if (s.substr(6)==""){
									current_path = "/";
									current_paths[current_user] = current_path;
								} else {
									current_path = s.substr(6);
									current_paths[current_user] = current_path;
								}
								cout<<"testing path:"<<current_path<<endl;

								bool success;
								SocketCommunicator sc_storage(storage_fd);
								configmap = sc_storage.configToMap(current_user, success);
								string content = drive_page(current_path, configmap);
								render_page(content, comm_fd);
							} else if (strcmp(get_command, "/movefile")==0){
								string content = drive_page(current_path, configmap);
								render_page(content, comm_fd);
							}else {
							}
							get = false;


						}
					} else if (strcmp(comm_3, "GET\0")==0){

						char *snippet;
						snippet = strtok(line, " ");
						snippet = strtok(NULL, " ");
						memset(get_command, 0, 30);
						strcat(get_command, snippet);
						get = true;

						if (vFlag) {
							string toprint = "GET" + string(get_command) +"\r\n";
							printf("[%d] C: %s", comm_fd, toprint.c_str());
						}

					} else if (strcmp(comm_4, "POST\0")==0){
						char *snippet;
						snippet = strtok(line, " ");
						snippet = strtok(NULL, " ");
						memset(post_command, 0, 30);
						strcat(post_command, snippet);
						post = true;

						if (vFlag) {
							string toprint = "POST" + string(post_command) +"\r\n";
							printf("[%d] C: %s", comm_fd, toprint.c_str());
						}
						cout << "<POST>: " << post_command << endl;
					} else if(strcmp(comm_4, "HEAD\0")==0){
						char *snippet;
						snippet = strtok(line, " ");
						snippet = strtok(NULL, " ");
						if (snippet == NULL){
							do_write(comm_fd, no_url_error, strlen(no_url_error));
						} else {
							memset(url, 0, 40);
							strcat(url, snippet);
						}
						get = true;
						head = true;
					}

					memset(buf, 0, current_size);
					memset(line, 0, strlen(line));
					buf += current_size;
					current_size = 0;
				}
			}
		}
		if (strlen(buf)>1){
			pointer = strlen(buf);
		} else {
			pointer = 0;
		}
	}
}

int parse_cookie(string post_head, bool &has_cookie) {
	// check for Cookie
	if (post_head.find("Cookie:")!=string::npos){
		has_cookie = true;
		//*** PARSE COOKIE INFORMATION ****//
		size_t username_index = post_head.find("username=");
		size_t sid_index = post_head.find("sid=", username_index);
		string current_user = post_head.substr(username_index+9, sid_index-username_index-11);
		string sid = post_head.substr(sid_index+4).c_str();
		return stoi(sid.c_str());

	} else {
		// No Cookie
		has_cookie = false;
		return 0;
	}
}

/**
 * Connects to the backend master. When a new primary is selected, the master will alert this thread
 * which updates the global variable storage_fd.
 */
static void *thread_handle_updateStorageSocket(void *arg) {
	// Create a TCP socket soley for communicating a new primary.
	int newPrimary_fd = connect_server(10000);

	char char_buf[BUFFSIZE];
	while (true) {
		int bytes_read = recv(newPrimary_fd, &char_buf[0], BUFFSIZE, 0);	// Block and wait for a new primary alert from master
		int newPrimaryPortno = strtoull(char_buf, NULL, 10);

//		printf("New portno %d\n", newPrimaryPortno);

		close(storage_fd);
		storage_fd = connect_server(newPrimaryPortno);
	}

	pthread_exit(NULL);
}

void* master_worker(void* arg) {

	int comm_fd = *(int*) arg;
	char ok[] = "+OK\r\n";
	printf("comm_fd is %d\n", comm_fd);

	while (true) {

		char buf[100];
		memset(buf, 0, 100);

		if (!do_read(comm_fd, buf, 100)) {
			printf("Error reading\n");
			pthread_exit(NULL);
		}

		string msg(buf);

		if (msg == "+heart\r\n") {
			// send heartbeat
			do_write(comm_fd, ok, strlen(ok));
			printf("Heatbeat sent\r\n");
		} else {
			int client_fd = connect_server(stoi(msg));
			pthread_t c_thread;
			int new_thread = pthread_create(&c_thread, NULL, worker, &client_fd);
			printf("Created new thread for client\r\n");
		}
	}

	pthread_exit(NULL);

}

int main(int argc, char *argv[]){
	int portno = 8000;
	int opt;
	bool pFlag = false;
	bool aFlag = false;
	while ((opt = getopt(argc, argv, "avp:")) != -1) {
			switch(opt){
			case 'p':
				pFlag = true;
				if (optarg){
					portno = atoi(optarg);
				}
				break;
			case 'a':
				aFlag = true;
				break;
			case 'v':
				vFlag = true;
				break;
			default:
				fprintf(stderr,"invalid syntax\n");
				exit(-1);
			}
	}

	if (aFlag == true){
		fprintf(stderr, "Team: T17 \n");
		exit(0);
	}

	//signal(SIGINT, signal_handler);
	// load balancer: checking heartbeat, sending clients to different frontend server

	// Socket for backend storage server communication
	int master_fd = connect_server(STORAGEPORT);
	int master_two = connect_server(MASTERFRONT);

	pthread_t newPrimary_thread;
	pthread_create(&newPrimary_thread, NULL, thread_handle_updateStorageSocket, nullptr);

	//pthread_t frontendMaster_thread;
	//pthread_create(&frontendMaster_thread, NULL, master_worker, &master_two);

	// Start server socket for clients
	// Socket File Descriptor
	servfd = socket(PF_INET, SOCK_STREAM, 0);

	// Return error when sockfd < 0
	if (servfd < 0) {
		fprintf(stderr, "Cannot open socket (%s)\n", strerror(errno));
		exit(1); // cannot open socket error
	}
	//Server socket
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
	servaddr.sin_port = htons(portno);

	 int c = 1;
	 int ret = setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, &c, sizeof(c));
	 if (ret < 0) {
	 	perror("ERROR reuse port number");
	 	exit (1);
	 }

	// Binding
	int b = bind(servfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	if (b<0){
		perror("ERROR when binding");
		exit(2); // cannot bind error
	}

	// Listening
	if (listen(servfd, 10)<0){
		perror("ERROR when listening");
		exit(3); // cannot listen error
	}

	while (1) {
		// Client Socket()
		struct sockaddr_in clientaddr;
		socklen_t clientaddrlen = sizeof(clientaddr);
		int *fd = (int*)malloc(sizeof(int));
		if ((*fd = accept(servfd, (struct sockaddr*)&clientaddr, &clientaddrlen))<0){
			perror("ERROR when accepting");
			exit(4);
		}
//		stor_fds[*fd] = storagefd;

		//storage_fds[*fd] = storagefd;
		//Dispatcher thread hands off connection to a worker
		num_threads++;
		fds[num_threads-1] = *fd;
		pthread_t thread;
		int new_thread = pthread_create(&thread, NULL, worker, fd);
	}
	close(storage_fd);
	close(master_fd);
	close(servfd);
	return 0;

}
