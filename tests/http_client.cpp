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

using namespace std;

struct state_t {
	void * ctx;
	void * socketIn;
	void * socketOut;
	void * socketFinal;
};

inline int send_data(void * socket, const void * data, size_t len){
	zmq_msg_t msg;
	assert(zmq_msg_init_size(&msg, len) == 0);
	memcpy(zmq_msg_data(&msg), data, len);
	int rc = 0;
	assert((rc = zmq_msg_send(&msg, socket, 0)) > 0);
	zmq_msg_close(&msg);
	return rc;
}

inline int send_data_more(void * socket, const void * data, size_t len){
	zmq_msg_t msg;
	assert(zmq_msg_init_size(&msg, len) == 0);
	memcpy(zmq_msg_data(&msg), data, len);
	int rc = 0;
	assert((rc = zmq_msg_send(&msg, socket, ZMQ_SNDMORE)) > 0);
	zmq_msg_close(&msg);
	return rc;
}

inline int recv_data(void * socket, function<int(char * data, size_t len)> process_input){
	zmq_msg_t msg;

	assert(zmq_msg_init(&msg) == 0);
	assert(zmq_msg_recv(&msg, socket, 0) >= 0);
	int rc = process_input(reinterpret_cast<char*>(zmq_msg_data(&msg)), zmq_msg_size(&msg));
	zmq_msg_close(&msg);

	return rc;
}

typedef function < void(state_t & state) > StatefullFuncton;

void prepareStreamInput(const string & hostname, state_t & state, StatefullFuncton callback){
	assert(state.socketIn = zmq_socket(state.ctx, ZMQ_STREAM));
	assert(state.socketOut = zmq_socket(state.ctx, ZMQ_PAIR));

	string endpointIn = "tcp://" + hostname + ":443";
	string endpointOut = "inproc://ztls_encrypted";

	int linger = 2000;
	assert(zmq_setsockopt(state.socketIn, ZMQ_LINGER, &linger, sizeof(linger)) == 0);
	assert(zmq_setsockopt(state.socketOut, ZMQ_LINGER, &linger, sizeof(linger)) == 0);

	assert(zmq_connect(state.socketIn, endpointIn.c_str()) == 0);
	assert(zmq_connect(state.socketOut, endpointOut.c_str()) == 0);

	callback(state);

	zmq_close(state.socketOut);
	zmq_close(state.socketIn);
}

void prepareStreamOutput(state_t & state, StatefullFuncton callback){
	assert(state.socketFinal = zmq_socket(state.ctx, ZMQ_PAIR));

	string endpointFinal = "inproc://ztls_decrypted";

	int linger = 2000;
	assert(zmq_setsockopt(state.socketFinal, ZMQ_LINGER, &linger, sizeof(linger)) == 0);

	assert(zmq_connect(state.socketFinal, endpointFinal.c_str()) == 0);

	callback(state);

	zmq_close(state.socketFinal);
}

/*
	Client request

	inSocket - server
	outSocket - client (this host)
*/
bool transmitOutput(const string & clientID, void * inSocket, void * outSocket){
	zmq_msg_t msgIn;
	assert(zmq_msg_init(&msgIn) == 0);
	zmq_msg_recv(&msgIn, outSocket, 0);

	{
		//send client ID
		send_data_more(inSocket, clientID.c_str(), clientID.length());

		//send data
		zmq_msg_t msgOut;
		assert(zmq_msg_init(&msgOut) == 0);
		assert(zmq_msg_copy(&msgOut, &msgIn) == 0);
		assert(zmq_msg_send(&msgOut, inSocket, ZMQ_SNDMORE) > 0);
		zmq_msg_close(&msgOut);

		cout << "Sent: " << zmq_msg_size(&msgIn) << " bytes\n";
	}

	zmq_msg_close(&msgIn);
	return true;
}

/*
	Server response

	inSocket - server
	outSocket - client (this host)
*/
bool transmitInput(void * inSocket, void * outSocket){
	// get client ID
	string currentClientID;
	{
		recv_data(inSocket, [&](char *data, size_t len) -> int{
			currentClientID = string(data, len);
			return 0;
		});
	}
	// get actual data
	{
		zmq_msg_t msgIn;
		assert(zmq_msg_init(&msgIn) == 0);
		assert(zmq_msg_recv(&msgIn, inSocket, 0) >= 0);

		//send data further inside
		size_t length = zmq_msg_size(&msgIn);
		if (length > 0){
			cout << "Received: " << length << " bytes\n";
			{
				zmq_msg_t msgOut;
				assert(zmq_msg_init(&msgOut) == 0);
				assert(zmq_msg_copy(&msgOut, &msgIn) == 0);
				assert(zmq_msg_send(&msgOut, outSocket, 0) >= 0);
				zmq_msg_close(&msgOut);
			}

			zmq_msg_close(&msgIn);
			return true;
		}
		else{
			{
				cout << "Server initiated close\n";
				assert(zmq_close(outSocket) == 0);
				outSocket = nullptr;
			}

			zmq_msg_close(&msgIn);
			return false;
		}
	}
	return true;
}

void closeRemote(const string & clientID, void * inSocket){
	zmq_pollitem_t poll;
	memset(&poll, 0, sizeof(zmq_pollitem_t));
	poll.socket = inSocket;
	poll.events = ZMQ_POLLOUT;

	int rcOut = zmq_poll(&poll, 1, -1);
	if (rcOut > 0){
		//send client ID
		send_data_more(poll.socket, clientID.c_str(), clientID.length());

		//send data
		zmq_msg_t msgOut;
		assert(zmq_msg_init_size(&msgOut, 0) == 0);
		assert(zmq_msg_send(&msgOut, poll.socket, 0) > 0);
		zmq_msg_close(&msgOut);

		assert(zmq_close(inSocket));
		inSocket = nullptr;
	}
	else if (rcOut == -1){
		if (zmq_errno() == ETERM){
			cout << "Server connection already closed\n";
		}
	}
}


bool processStreamInput(state_t & state, string clientID){
	zmq_pollitem_t pollIn[2], pollOut[2];

	memset(&pollIn, 0, sizeof(zmq_pollitem_t)*2);
	memset(&pollOut, 0, sizeof(zmq_pollitem_t)*2);

	pollIn[0].socket = state.socketIn;
	pollIn[0].events = ZMQ_POLLIN;
	pollIn[1].socket = state.socketOut;
	pollIn[1].events = ZMQ_POLLOUT;

	pollOut[0].socket = state.socketIn;
	pollOut[0].events = ZMQ_POLLOUT;
	pollOut[1].socket = state.socketOut;
	pollOut[1].events = ZMQ_POLLIN;

	int rcOut = zmq_poll(pollOut, 2, -1);
	if (rcOut >= 2){

		//output to server
		if ((pollOut[1].revents & ZMQ_POLLIN) && (pollOut[0].revents & ZMQ_POLLOUT)){
			transmitOutput(clientID, pollOut[0].socket, pollOut[1].socket);
		}
	}
	else if (rcOut == -1){
		if (zmq_errno() == ETERM){
			closeRemote(clientID, pollOut[0].socket);
			cout << "Server connection closed\n";
		}
	}

	int rcIn = zmq_poll(pollIn, 2, -1);
	if (rcIn >= 2){
		//input from server
		if ((pollIn[1].revents & ZMQ_POLLOUT) && (pollIn[0].revents & ZMQ_POLLIN)){
			return transmitInput(pollIn[0].socket, pollIn[1].socket);
		}
	}
	else if (rcIn == -1){
		if (zmq_errno() == ETERM){
			cout << "Server connection closed\n";
		}
	}

	return true;
}

int main(int argc, char ** argv, char ** env){
	void * ctx = nullptr;
	state_t state;
	state.ctx = zmq_ctx_new();
	mutex m;
	condition_variable cv;
	bool ready = false;
	atomic_bool inputProcessorRunning;
	inputProcessorRunning.store(true);
	string hostname = "google.com";

	thread inputProcessor = thread([&](){

		prepareStreamInput(hostname, state, [&](state_t & state){
			string endpointIn = "inproc://ztls_encrypted";
			string endpointOut = "inproc://ztls_decrypted";
			{
				lock_guard<mutex> lk(m);
				ctx = ztls_client_init_with_ctx(state.ctx, endpointIn.c_str(), endpointOut.c_str());
				ready = true;
			}
			// mbedtls BIO callback functions should be initialized by this moment
			cv.notify_one();

			string clientID;
			zmq_pollitem_t pollIn;
			memset(&pollIn, 0, sizeof(zmq_pollitem_t));

			pollIn.socket = state.socketIn;
			pollIn.events = ZMQ_POLLIN;

			int rc = zmq_poll(&pollIn, 1, -1);
			if ((rc > 0) && (pollIn.revents & ZMQ_POLLIN)){
				recv_data(pollIn.socket, [&](char * data, size_t len) -> int{
					clientID = string(data, len);
					return 0;
				});

				size_t initLength = recv_data(pollIn.socket, [&](char * data, size_t len) -> int{
					return len;
				});

				if (initLength == 0){
					bool running;
					do {
						running = inputProcessorRunning.load();
						if (!processStreamInput(state, clientID)){
							inputProcessorRunning.store(false);
							break;
						}
					} while (running);
				}
			}
			ztls_client_destroy(ctx);
		});
	});

	thread outputProcessor = thread([&](){
		prepareStreamOutput(state, [&](state_t & state){
			string request = "GET / HTTP/1.1\n\n";

			zmq_pollitem_t pollIn;
			memset(&pollIn, 0, sizeof(zmq_pollitem_t));

			pollIn.socket = state.socketFinal;
			pollIn.events = ZMQ_POLLIN | ZMQ_POLLOUT;

			unique_lock<mutex> lk(m);
			cv.wait(lk, [&]{return ready; });
			bool running = true;

			if (ztls_client_connect(ctx, hostname.c_str())){
				do {
					int rc = zmq_poll(&pollIn, 1, -1);
					if (rc > 0){
						if (pollIn.revents & ZMQ_POLLIN){
							recv_data(pollIn.socket, [&](char * data, size_t len) -> int{
								string response = string(data, len);
								cout << response;
								running = false;
								if (ztls_client_close(ctx)){
									inputProcessorRunning.store(false);
								}
								return 0;
							});
						}

						if (pollIn.revents & ZMQ_POLLOUT){
							send_data(pollIn.socket, request.c_str(), request.length() + 1);
							pollIn.events = ZMQ_POLLIN;
						}
					}
				} while (running);
			}

		});
	});

	inputProcessor.join();
	outputProcessor.join();

	assert(zmq_ctx_destroy(state.ctx) == 0);
	return 0;
}