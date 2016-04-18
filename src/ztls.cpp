#include "common.hpp"
#include "ztls.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509.h>
#include <mbedtls/timing.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

#include <cassert>
#include <string>
#include <thread>
#include <iostream>

using namespace std;

#define ZTLS_INPUT_BUFFER_SIZE 8192
#define ZTLS_ERROR_MESSAGE_SIZE 4096
#define ZTLS_MAX_COMMAND_BUFFER_SIZE 32

namespace ztls {
	class SimpleBuffer {
	private:
		size_t bufferSize;
		char * buffer;
		size_t pos;
	public:
		SimpleBuffer(const size_t bufferSize){
			this->bufferSize = bufferSize;
			buffer = new char[bufferSize];
			pos = 0;
		}
		~SimpleBuffer(){
			delete buffer;
		}

		bool push(const char * data, size_t length){
			// store whole data
			if ((pos + length) <= bufferSize){
				memcpy(buffer + pos, data, length);
				pos += length;
				return true;
			}
			else{
				return false;
			}
		}

		bool pop(char * output, size_t length){
			if (pos >= length){
				memcpy(output, buffer, length);
				memmove(buffer, buffer + length, bufferSize - length);
				if (pos < length){
					pos = 0;
				}
				else{
					pos -= length;
				}
				return true;
			}
			else{
				return false;
			}
		}

		bool hasEnough(size_t length){
			return (pos >= length);
		}
	};

	enum state_name_t {
		ZTLS_HANDSHAKE,
		ZTLS_TRANSPORTING,
		ZTLS_INACTIVE,
		ZTLS_QUITING,
		ZTLS_FINISHED
	};

	struct state_t {
		mbedtls_entropy_context entropy_context;
		mbedtls_ctr_drbg_context CTRDBG_context;
		mbedtls_ssl_context SSL_context;
		mbedtls_x509_crt CA_cert;
		mbedtls_timing_delay_context timing_delay_context;
		mbedtls_ssl_config SSL_config;
		string seed;
		string hostname;

		string endpoint_in;
		string endpoint_out;
		string endpoint_control;
		void * zmq_context;
		void * zmq_socket_in;
		void * zmq_socket_out;
		void * zmq_socket_control;
		zmq_pollitem_t zmq_poll_in;
		zmq_pollitem_t zmq_poll_out;
		zmq_pollitem_t zmq_poll_control;

		SimpleBuffer * input_buffer;
		state_name_t state;
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

	typedef function<void(char * data, int length)> recv_process_data_fn;
	typedef function<bool(recv_process_data_fn process_data)> recv_more_fn;

	inline int recv_more_data(void * socket, function<int(recv_more_fn recvMore)> process_input){
		recv_more_fn fn = [&](recv_process_data_fn process_data) -> bool {
			zmq_msg_t msg;
			assert(zmq_msg_init(&msg) == 0);
			assert(zmq_msg_recv(&msg, socket, 0) >= 0);
			process_data(reinterpret_cast<char*>(zmq_msg_data(&msg)), zmq_msg_size(&msg));
			zmq_msg_close(&msg);
			return zmq_msg_more(&msg);
		};

		return process_input(fn);
	}

	void send_tls_error(state_t * state, int rc){
		if (rc != 0){
			char errorMsg[ZTLS_ERROR_MESSAGE_SIZE];
			mbedtls_strerror(rc, errorMsg, ZTLS_ERROR_MESSAGE_SIZE);

			state->zmq_poll_control.events = ZMQ_POLLOUT;
			int result = zmq_poll(&state->zmq_poll_control, 1, -1);

			if (result >= 0 && (state->zmq_poll_control.revents & ZMQ_POLLOUT)){
				char data[] = "ERROR";
				send_data_more(state->zmq_poll_control.socket, data, strlen(data)+1);
				send_data(state->zmq_poll_control.socket, errorMsg, strlen(errorMsg)+1);
			}
		}
	}

	void send_control_message(state_t * state, string message){
		state->zmq_poll_control.events = ZMQ_POLLOUT;
		int result = zmq_poll(&state->zmq_poll_control, 1, -1);

		if (result >= 0 && (state->zmq_poll_control.revents & ZMQ_POLLOUT)){
			char data[] = "NOTIFY";
			send_data_more(state->zmq_poll_control.socket, data, strlen(data) + 1);
			send_data(state->zmq_poll_control.socket, message.c_str(), message.length() + 1);
		}
	}

	namespace tls {
		bool client_close_tls(state_t * state);
		void client_destroy_tls(state_t * state);
	};

	namespace transport {
		int send_cb(void * context_data, const unsigned char * data, size_t len){
			state_t * state = reinterpret_cast<state_t*>(context_data);

			state->zmq_poll_in.events = ZMQ_POLLOUT;
			int result = zmq_poll(&state->zmq_poll_in, 1, -1);

			if (result > 0){
				return send_data(state->zmq_poll_in.socket, data, len);
			}
			else if (result == -1){
				if (zmq_errno() == ETERM){
					return EOF;
				}
				else{
					return -1;
				}
			}
			else{
				return MBEDTLS_ERR_SSL_TIMEOUT;
			}
		}

		bool dataOnInput(state_t * state, uint32_t t){
			state->zmq_poll_in.events = ZMQ_POLLIN;
			return (zmq_poll(&state->zmq_poll_in, 1, t) > 0);
		}

		int recv_timeout_cb(void * context_data, unsigned char * data, size_t len, uint32_t t){
			state_t * state = reinterpret_cast<state_t*>(context_data);

			while (!state->input_buffer->hasEnough(len)){
				state->zmq_poll_in.events = ZMQ_POLLIN;
				//translate timeout value from mbedtls to ZeroMQ notation
				if (t == 0){
					t = -1;
				}
				int result = zmq_poll(&state->zmq_poll_in, 1, t);

				if (result > 0){
					int rc = recv_data(state->zmq_poll_in.socket, [&](char * data, size_t length) -> int{
						if (length > 0){
							return (state->input_buffer->push(reinterpret_cast<char*>(data), length)) ? 1 : -1;
						}
						else{
							return 0;
						}
					});
					//server quit
					if (rc == 0){
						cout << "Detected server initiated close\n";
						return EOF;
					}else if (rc < 0){
						//buffer is full!
						return -1;
					}
				}
				else if (result == -1){
					if (zmq_errno() == ETERM){
						cout << "Detected server initiated close\n";
						return EOF;
					}
					else{
						return -1;
					}
				}
				else{
					return MBEDTLS_ERR_SSL_TIMEOUT;
				}
			}

			if (state->input_buffer->hasEnough(len)){
				state->input_buffer->pop(reinterpret_cast<char*>(data), len);
				return len;
			}
			else{
				return MBEDTLS_ERR_SSL_WANT_READ;
			}
		}

		inline int recv_cb(void * context_data, unsigned char * data, size_t len){
			return recv_timeout_cb(context_data, data, len, -1);
		}

		void init(state_t * state){
			assert(state->zmq_socket_in = zmq_socket(state->zmq_context, ZMQ_PAIR));
			assert(state->zmq_socket_out = zmq_socket(state->zmq_context, ZMQ_PAIR));
			assert(state->zmq_socket_control = zmq_socket(state->zmq_context, ZMQ_PAIR));

			int linger = 2000;
			assert(zmq_setsockopt(state->zmq_socket_in, ZMQ_LINGER, &linger, sizeof(linger)) == 0);
			assert(zmq_setsockopt(state->zmq_socket_out, ZMQ_LINGER, &linger, sizeof(linger)) == 0);
			assert(zmq_setsockopt(state->zmq_socket_control, ZMQ_LINGER, &linger, sizeof(linger)) == 0);

			assert(zmq_bind(state->zmq_socket_in, state->endpoint_in.c_str()) == 0);
			assert(zmq_bind(state->zmq_socket_out, state->endpoint_out.c_str()) == 0);
			assert(zmq_bind(state->zmq_socket_control, state->endpoint_control.c_str()) == 0);

			memset(&state->zmq_poll_in, 0, sizeof(zmq_pollitem_t));
			memset(&state->zmq_poll_out, 0, sizeof(zmq_pollitem_t));
			memset(&state->zmq_poll_control, 0, sizeof(zmq_pollitem_t));

			state->zmq_poll_in.socket = state->zmq_socket_in;
			state->zmq_poll_in.events = ZMQ_POLLIN;
			state->zmq_poll_out.socket = state->zmq_socket_out;
			state->zmq_poll_out.events = ZMQ_POLLIN;
			state->zmq_poll_control.socket = state->zmq_socket_control;
			state->zmq_poll_control.events = ZMQ_POLLIN;
		}

		void discard_messages(void * socket){
			zmq_pollitem_t poll_item;
			memset(&poll_item, 0, sizeof(zmq_pollitem_t));
			poll_item.socket = socket;
			poll_item.events = ZMQ_POLLIN;

			int result = zmq_poll(&poll_item, 1, 0);
			if ((result > 0) && (poll_item.revents & ZMQ_POLLIN)){
				recv_data(poll_item.socket, [&](char *data, size_t len) -> int {
					cout << len << " byes discarded\n";
					return 0;
				});
			}
		}


		void destroy(state_t * state){
			discard_messages(state->zmq_socket_control);
			discard_messages(state->zmq_socket_out);
			discard_messages(state->zmq_socket_in);

			zmq_close(state->zmq_socket_control);
			zmq_close(state->zmq_socket_out);
			zmq_close(state->zmq_socket_in);
		}

		bool process_transport(state_t * state){
			if (state->SSL_context.state == MBEDTLS_SSL_SERVER_FINISHED){
				tls::client_close_tls(state);
				tls::client_destroy_tls(state);
				return false;
			}

			state->zmq_poll_out.events = ZMQ_POLLIN | ZMQ_POLLOUT;
			int result = zmq_poll(&state->zmq_poll_out, 1, 500);

			if (result > 0){
				zmq_msg_t msgIn;

				if (state->zmq_poll_out.revents & ZMQ_POLLIN){
					int rc = recv_data(state->zmq_poll_out.socket, [&](char * data, size_t length) -> int{
						int rc = 0;
						do {
							rc = mbedtls_ssl_write(&state->SSL_context, reinterpret_cast<unsigned char *>(data), length);
						} while ((rc == MBEDTLS_ERR_SSL_WANT_READ) || (rc == MBEDTLS_ERR_SSL_WANT_WRITE));

						return rc;
					});
				}

				if (state->zmq_poll_out.revents & ZMQ_POLLOUT){
					if (dataOnInput(state, 0))
					{
						int rc = 0;
						char buffer[ZTLS_INPUT_BUFFER_SIZE];

						do{
							rc = mbedtls_ssl_read(&state->SSL_context, reinterpret_cast<unsigned char*>(buffer), ZTLS_INPUT_BUFFER_SIZE);
						} while ((rc == MBEDTLS_ERR_SSL_WANT_READ) || (rc == MBEDTLS_ERR_SSL_WANT_WRITE));

						if (rc > 0){
							send_data(state->zmq_poll_out.socket, buffer, rc);
						}
						else{
							if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY){
								tls::client_close_tls(state);
								tls::client_destroy_tls(state);
								return false;
							}
						}
					}
				}
			}
			return true;
		}
	};

	namespace tls {
		static void my_debug(void *ctx, int level, const char *file, int line, const char *str)	{
			((void)level);

			fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
			fflush((FILE *)ctx);
		}

		void client_init_tls(state_t * state){
			//init data structures
			mbedtls_ctr_drbg_init(&state->CTRDBG_context);
			mbedtls_entropy_init(&state->entropy_context);
			mbedtls_ssl_config_init(&state->SSL_config);
			mbedtls_ssl_init(&state->SSL_context);
			mbedtls_x509_crt_init(&state->CA_cert);

			assert(
				mbedtls_ctr_drbg_seed(
				&state->CTRDBG_context,
				mbedtls_entropy_func,
				&state->entropy_context,
				reinterpret_cast<const unsigned char*>(state->seed.c_str()),
				state->seed.length()
				) == 0
				);

			mbedtls_debug_set_threshold(1);
			//setup SSL/TLS
			memset(&state->SSL_config, 0, sizeof(mbedtls_ssl_config));
			assert(mbedtls_ssl_config_defaults(&state->SSL_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0);
			state->SSL_config.authmode = MBEDTLS_SSL_VERIFY_OPTIONAL;
			mbedtls_ssl_conf_ca_chain(&state->SSL_config, &state->CA_cert, nullptr);
			mbedtls_ssl_conf_rng(&state->SSL_config, mbedtls_entropy_func, &state->entropy_context);
			mbedtls_ssl_conf_dbg(&state->SSL_config, my_debug, stdout);

			assert(mbedtls_ssl_setup(&state->SSL_context, &state->SSL_config) == 0);
			assert(mbedtls_ssl_set_hostname(&state->SSL_context, state->hostname.c_str()) == 0);

			mbedtls_ssl_set_bio(&state->SSL_context, state, transport::send_cb, transport::recv_cb, transport::recv_timeout_cb);
			mbedtls_ssl_set_timer_cb(&state->SSL_context, &state->timing_delay_context, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
		}

		bool client_close_tls(state_t * state){
			state->state = state_name_t::ZTLS_QUITING;
			int rc = mbedtls_ssl_close_notify(&state->SSL_context);
			if (rc == 0){
				zmq_close(state->zmq_socket_in);
				zmq_close(state->zmq_socket_out);
				state->zmq_socket_in = nullptr;
				state->zmq_socket_out = nullptr;
				state->state = state_name_t::ZTLS_FINISHED;
				return true;
			}
			else{
				send_tls_error(state, rc);
				return false;
			}
		}

		bool client_handshake(state_t * state){
			state->state = state_name_t::ZTLS_HANDSHAKE;
			int rc = mbedtls_ssl_handshake(&state->SSL_context);
			if (rc == 0){
				state->state = state_name_t::ZTLS_TRANSPORTING;
				return true;
			}
			else{
				send_tls_error(state, rc);
				return false;
			}
		}

		void client_destroy_tls(state_t * state){
			state->state = state_name_t::ZTLS_INACTIVE;
			mbedtls_x509_crt_free(&state->CA_cert);
			mbedtls_ssl_free(&state->SSL_context);
			mbedtls_ssl_config_free(&state->SSL_config);
			mbedtls_entropy_free(&state->entropy_context);
			mbedtls_ctr_drbg_free(&state->CTRDBG_context);
		}

		void process_commands(state_t * state){
			state->zmq_poll_control.events = ZMQ_POLLIN;
			int result = zmq_poll(&state->zmq_poll_control, 1, 0);
			
			if (result > 0){
				recv_more_data(state->zmq_poll_control.socket, [&](ztls::recv_more_fn recv) -> int{
					char command_name[ZTLS_MAX_COMMAND_BUFFER_SIZE + 1];
					bool more = false;

					//command name
					more = recv([&](char * data, int length){
						if (length > 0){
							memcpy(command_name, data, (length <= ZTLS_MAX_COMMAND_BUFFER_SIZE) ? length : ZTLS_MAX_COMMAND_BUFFER_SIZE);
							command_name[(length <= ZTLS_MAX_COMMAND_BUFFER_SIZE) ? length + 1 : ZTLS_MAX_COMMAND_BUFFER_SIZE + 1] = 0;
						}
						else{
							command_name[0] = 0;
						}
					});

					if ((strncmp(command_name, "CONNECT", ZTLS_MAX_COMMAND_BUFFER_SIZE) == 0) && more){
						recv([&](char * data, int length){
							if (length > 0){
								state->hostname = string(data, length);
							}
						});

						if (state->state == state_name_t::ZTLS_INACTIVE){
							client_init_tls(state);
							if (client_handshake(state)){
								send_control_message(state, "OK");
							}else{
								client_destroy_tls(state);
							}
						}
						else if (state->state == state_name_t::ZTLS_TRANSPORTING){
							client_close_tls(state);
							client_destroy_tls(state);
							client_init_tls(state);
							if (client_handshake(state)){
								send_control_message(state, "OK");
							}else{
								client_destroy_tls(state);
							}
						}
					}
					else if ((strncmp(command_name, "CLOSE", ZTLS_MAX_COMMAND_BUFFER_SIZE) == 0)){
						if (state->state == state_name_t::ZTLS_TRANSPORTING){
							if (client_close_tls(state)){
								send_control_message(state, "OK");
							}
							client_destroy_tls(state);
						}
					}

					return 0;
				});
			}

		}

		state_t * client_init_state(void * zmq_context, const string endpoint_in, const string endpoint_out, const string endpoint_control){
			assert(zmq_context != nullptr);
			state_t * state = new state_t;

			state->seed = "ztls_test";
			state->endpoint_in = endpoint_in;
			state->endpoint_out = endpoint_out;
			state->endpoint_control = endpoint_control;

			state->state = ZTLS_INACTIVE;

			state->input_buffer = new SimpleBuffer(ZTLS_INPUT_BUFFER_SIZE);
			state->zmq_context = zmq_context;

			transport::init(state);
			return state;
		}

		void client_destroy_state(state_t * state){
			transport::destroy(state);
			assert(zmq_ctx_shutdown(state->zmq_context) == 0);

			delete state->input_buffer;
			delete state;
		}
	};
};

struct ztls_state_public {
	void * zmq_context;
	void * zmq_socket_control;
	zmq_pollitem_t zmq_poll_control;
	thread worker;
	bool own_context;
};

void * ztls_client_init_with_ctx(void * zmq_context, const char * endpoint_in, const char * endpoint_out){
	assert(endpoint_in != nullptr);
	assert(endpoint_out != nullptr);

	string endpoint_control = "inproc://ztls_control";

	ztls_state_public * state = new ztls_state_public;

	state->zmq_context = zmq_context;
	state->own_context = false;

	state->zmq_socket_control = zmq_socket(state->zmq_context, ZMQ_PAIR);

	int linger = 2000;
	assert(zmq_setsockopt(state->zmq_socket_control, ZMQ_LINGER, &linger, sizeof(linger)) == 0);

	memset(&state->zmq_poll_control, 0, sizeof(zmq_pollitem_t));
	state->zmq_poll_control.socket = state->zmq_socket_control;

	assert(zmq_connect(state->zmq_socket_control, endpoint_control.c_str()) == 0);

	state->worker = std::thread([&](void * zmq_context, const string endpoint_in, const string endpoint_out, const string endpoint_control){
		ztls::state_t * private_state = ztls::tls::client_init_state(zmq_context, endpoint_in, endpoint_out, endpoint_control);

		do {
			ztls::tls::process_commands(private_state);
			if (private_state->state == ztls::ZTLS_TRANSPORTING){
				ztls::transport::process_transport(private_state);
			}
		} while (private_state->state != ztls::ZTLS_FINISHED);

		ztls::tls::client_destroy_state(private_state);
	}, state->zmq_context, endpoint_in, endpoint_out, endpoint_control);
	return state;
}

void * ztls_client_init(const char * endpoint_in, const char * endpoint_out){
	void * _state = ztls_client_init_with_ctx(zmq_ctx_new(), endpoint_in, endpoint_out);
	ztls_state_public * state = reinterpret_cast<ztls_state_public*>(_state);
	state->own_context = true;
	return _state;
}

bool ztls_client_destroy(void * _state){
	assert(_state != nullptr);

	ztls_state_public * state = reinterpret_cast<ztls_state_public*>(_state);
	state->zmq_poll_control.events = ZMQ_POLLOUT;
	int result = zmq_poll(&state->zmq_poll_control, 1, -1);

	if (result >= 0 && (state->zmq_poll_control.revents & ZMQ_POLLOUT)){
		char data[] = "CLOSE";

		ztls::send_data(state->zmq_poll_control.socket, data, strlen(data)+1);

		zmq_close(state->zmq_socket_control);
		state->worker.join();
		
		if (state->own_context){
			zmq_ctx_destroy(state->zmq_context);
		}
		delete state;
		return true;
	}
	else{
		return false;
	}
}

bool ztls_client_close(void * _state, char * error_message, size_t max_error_message_length){
	assert(_state != nullptr);

	ztls_state_public * state = reinterpret_cast<ztls_state_public*>(_state);
	state->zmq_poll_control.events = ZMQ_POLLOUT;
	int result = zmq_poll(&state->zmq_poll_control, 1, -1);

	if (result >= 0 && (state->zmq_poll_control.revents & ZMQ_POLLOUT)){
		{
			char data[] = "CLOSE";

			ztls::send_data(state->zmq_poll_control.socket, data, strlen(data) + 1);

		}

		{
			state->zmq_poll_control.events = ZMQ_POLLIN;
			int result = zmq_poll(&state->zmq_poll_control, 1, -1);
			if (result >= 0 && (state->zmq_poll_control.revents & ZMQ_POLLIN)){
				bool return_state = false;

				ztls::recv_more_data(state->zmq_poll_control.socket, [&](ztls::recv_more_fn recv) -> int {
					char message_type[ZTLS_MAX_COMMAND_BUFFER_SIZE + 1];
					char message_content[ZTLS_ERROR_MESSAGE_SIZE + 1];
					bool more = false;

					//command name
					more = recv([&](char * data, int length){
						if (length > 0){
							memcpy(message_type, data, (length <= ZTLS_MAX_COMMAND_BUFFER_SIZE) ? length : ZTLS_MAX_COMMAND_BUFFER_SIZE);
							message_type[(length <= ZTLS_MAX_COMMAND_BUFFER_SIZE) ? length + 1 : ZTLS_MAX_COMMAND_BUFFER_SIZE + 1] = 0;
						}
						else{
							message_type[0] = 0;
						}
					});

					if (more){
						recv([&](char * data, int length){
							if (length > 0){
								memcpy(message_content, data, (length <= ZTLS_ERROR_MESSAGE_SIZE) ? length : ZTLS_ERROR_MESSAGE_SIZE);
								message_content[(length <= ZTLS_ERROR_MESSAGE_SIZE) ? length + 1 : ZTLS_ERROR_MESSAGE_SIZE + 1] = 0;
							}
							else{
								message_content[0] = 0;
							}
						});
					}
					else{
						message_content[0] = 0;
					}

					if (strncmp(message_type, "NOTIFY", ZTLS_MAX_COMMAND_BUFFER_SIZE) == 0){
						if (strncmp(message_content, "OK", ZTLS_ERROR_MESSAGE_SIZE) == 0){
							return_state = true;
						}
					}
					else if (strncmp(message_type, "ERROR", ZTLS_MAX_COMMAND_BUFFER_SIZE) == 0){
						return_state = false;
						if (error_message){
							strncpy(error_message, message_content, max_error_message_length);
						}
					}

					return 0;
				});

				return return_state;
			}
		}
		return true;
	}
	return false;
}

bool ztls_client_connect(void * _state, const char * hostname, char * error_message, size_t max_error_message_length){
	assert(_state != nullptr);
	assert(hostname != nullptr);
	ztls_state_public * state = reinterpret_cast<ztls_state_public*>(_state);

	state->zmq_poll_control.events = ZMQ_POLLOUT;
	int result = zmq_poll(&state->zmq_poll_control, 1, -1);

	if (result > 0 && (state->zmq_poll_control.revents & ZMQ_POLLOUT)){
		{
			char data[] = "CONNECT";

			ztls::send_data_more(state->zmq_poll_control.socket, data, strlen(data) + 1);
			ztls::send_data(state->zmq_poll_control.socket, hostname, strlen(hostname) + 1);
		}
		{
			state->zmq_poll_control.events = ZMQ_POLLIN;
			int result = zmq_poll(&state->zmq_poll_control, 1, -1);
			if (result >= 0 && (state->zmq_poll_control.revents & ZMQ_POLLIN)){
				bool return_state = false;
				
				ztls::recv_more_data(state->zmq_poll_control.socket, [&](ztls::recv_more_fn recv) -> int {
					char message_type[ZTLS_MAX_COMMAND_BUFFER_SIZE + 1];
					char message_content[ZTLS_ERROR_MESSAGE_SIZE + 1];
					bool more = false;

					//command name
					more = recv([&](char * data, int length){
						if (length > 0){
							memcpy(message_type, data, (length <= ZTLS_MAX_COMMAND_BUFFER_SIZE) ? length : ZTLS_MAX_COMMAND_BUFFER_SIZE);
							message_type[(length <= ZTLS_MAX_COMMAND_BUFFER_SIZE) ? length + 1 : ZTLS_MAX_COMMAND_BUFFER_SIZE + 1] = 0;
						}
						else{
							message_type[0] = 0;
						}
					});

					if (more){
						recv([&](char * data, int length){
							if (length > 0){
								memcpy(message_content, data, (length <= ZTLS_ERROR_MESSAGE_SIZE) ? length : ZTLS_ERROR_MESSAGE_SIZE);
								message_content[(length <= ZTLS_ERROR_MESSAGE_SIZE) ? length + 1 : ZTLS_ERROR_MESSAGE_SIZE + 1] = 0;
							}
							else{
								message_content[0] = 0;
							}
						});
					}
					else{
						message_content[0] = 0;
					}

					if (strncmp(message_type, "NOTIFY", ZTLS_MAX_COMMAND_BUFFER_SIZE) == 0){
						if (strncmp(message_content, "OK", ZTLS_ERROR_MESSAGE_SIZE) == 0){
							return_state = true;
						}
					}
					else if(strncmp(message_type, "ERROR", ZTLS_MAX_COMMAND_BUFFER_SIZE) == 0){
						return_state = false;
						if (error_message){
							strncpy(error_message, message_content, max_error_message_length);
						}
					}

					return 0;
				});

				return return_state;
			}
		}
	}
	return false;
}

