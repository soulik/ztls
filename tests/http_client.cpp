#include <zmq.h>
#include "ztls.hpp"
#include <string>
#include <functional>
#include <thread>
#include <cassert>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>

using namespace std;

inline string sprintf_ex(const string & fmt, ...){
	va_list args;
	va_start(args, fmt);
	vector<char> buf(vsnprintf(nullptr, 0, fmt.c_str(), args)); // note +1 for null terminator
	vsnprintf(buf.data(), buf.size(), fmt.c_str(), args);
	va_end(args);
	return string(buf.data(), buf.size());
}

inline int send_data(void * socket, const void * data, size_t len){
	zmq_msg_t msg;
	int rc = zmq_msg_init_size(&msg, len);
	assert(rc == 0);
	memcpy(zmq_msg_data(&msg), data, len);
	rc = zmq_msg_send(&msg, socket, 0);
	assert(rc >= 0);
	zmq_msg_close(&msg);
	return rc;
}

inline int send_data_more(void * socket, const void * data, size_t len){
	zmq_msg_t msg;
	int rc = zmq_msg_init_size(&msg, len);
	assert(rc == 0);
	memcpy(zmq_msg_data(&msg), data, len);
	rc = zmq_msg_send(&msg, socket, ZMQ_SNDMORE);
	assert(rc >= 0);
	zmq_msg_close(&msg);
	return rc;
}

inline int recv_data(void * socket, function<int(char * data, size_t len)> process_input){
	zmq_msg_t msg;

	int rc = zmq_msg_init(&msg);
	assert(rc == 0);
	rc = zmq_msg_recv(&msg, socket, 0);
	assert(rc >= 0);
	rc = process_input(reinterpret_cast<char*>(zmq_msg_data(&msg)), zmq_msg_size(&msg));
	zmq_msg_close(&msg);

	return rc;
}

class http_test {
private:
	void * ztls_state;
	void * ctx;
	void * socket;
	void * control_socket;
	zmq_pollitem_t poll_items[2];
public:
	http_test();
	~http_test();

	string test_get(const string & host, const string & url);
	void process_control_message(void * socket);
};

http_test::http_test(){
	ctx = zmq_ctx_new();
	string data_endpoint = "inproc://https_data";
	string control_endpoint = "inproc://ztls_control";

	ztls_state = ztls_client_new_with_ctx(ctx, data_endpoint.c_str(), control_endpoint.c_str());
	
	socket = zmq_socket(ctx, ZMQ_PAIR);
	control_socket = zmq_socket(ctx, ZMQ_PAIR);

	assert(socket);
	assert(control_socket);

	int linger = 2000;
	int rc = zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger));
	assert(rc == 0);
	rc = zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger));
	assert(rc == 0);

	rc = zmq_connect(socket, data_endpoint.c_str());
	assert(rc == 0);
	rc = zmq_connect(control_socket, control_endpoint.c_str());
	assert(rc == 0);

	memset(poll_items, 0, sizeof(zmq_pollitem_t) * 2);
	poll_items[0].socket = socket;
	poll_items[1].socket = control_socket;
}

http_test::~http_test(){
	int rc = zmq_close(control_socket);
	assert(rc == 0);

	rc = zmq_close(socket);
	assert(rc == 0);
	ztls_client_destroy(ztls_state);
	rc = zmq_ctx_term(ctx);
	assert(rc == 0);
}

void http_test::process_control_message(void * socket){
	string msg_type;
	string msg_content;

	recv_data(socket, [&](char * data, size_t len) -> int{
		msg_type = string(data, len);
		return 0;
	});
	recv_data(socket, [&](char * data, size_t len) -> int{
		msg_content = string(data, len);
		return 0;
	});

	cout << sprintf_ex("Control message: %s\n%s\n", msg_type.c_str(), msg_content.c_str());
}

string http_test::test_get(const string & host, const string & url){
	if (ztls_client_connect(ztls_state, host.c_str(), 443)){
		string result;
		const string request = sprintf_ex("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", url.c_str(), host.c_str());
		
		poll_items[0].events = ZMQ_POLLOUT;
		poll_items[1].events = ZMQ_POLLIN;

		if (zmq_poll(&(poll_items[0]), 1, -1) > 0){
			if (poll_items[0].revents & ZMQ_POLLOUT){
				if (send_data(poll_items[0].socket, request.c_str(), request.length()) > 0){
					poll_items[0].events = ZMQ_POLLIN;

					while (true){
						if (zmq_poll(poll_items, 2, -1) > 0){
							if (poll_items[0].revents & ZMQ_POLLIN){
								recv_data(poll_items[0].socket, [&](char * data, size_t len) -> int{
									result = string(data, len);
									cout << sprintf_ex("Received (%d bytes):\n", len) + result;
									return 0;
								});
							}

							if (poll_items[1].revents & ZMQ_POLLIN){
								process_control_message(poll_items[1].socket);
							}
						}
					}
				}
				else{
					cout << "Error sending request\n";
				}
			}

			if (poll_items[1].revents & ZMQ_POLLIN){
				process_control_message(poll_items[1].socket);
			}

		}
		else{
			cout << "Error polling\n";
		}

		ztls_client_close(ztls_state);
		return result;
	}
	else{
		poll_items[1].events = ZMQ_POLLIN;
		if (zmq_poll(&(poll_items[1]), 1, -1) > 0){
			if (poll_items[1].revents & ZMQ_POLLIN){
				process_control_message(poll_items[1].socket);
			}
		}
	}
	return "";
}


int main(int argc, char ** argv, char ** env){
	http_test test1;

	test1.test_get("google.com", "/search?q=test");
	return 0;
}