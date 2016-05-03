﻿#include "common.hpp"
#include "ztls_private.hpp"
#include "ztls.hpp"

#include <cstdio>
#include <string>
#include <thread>
#include <iostream>
#include <vector>

using namespace std;

namespace ztls {
	void tls_client::debug_fn(void *ctx, int level, const char *file, int line, const char *str)	{
		((void)level);

		fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
		fflush((FILE *)ctx);
	}

	tls_client::tls_client(mbedtls_ssl_send_t send_cb, mbedtls_ssl_recv_t recv_cb, mbedtls_ssl_recv_timeout_t recv_timeout_cb, void * context_data, function<int(int rc)> assert_tls_fn){
		strict_crt = false;
		assert_tls = assert_tls_fn;
		debug_level = 0;
		seed = "ztls_test";
		mbedtls_ctr_drbg_init(&CTRDBG_context);
		mbedtls_entropy_init(&entropy_context);
		mbedtls_ssl_config_init(&SSL_config);
		mbedtls_ssl_init(&SSL_context);
		mbedtls_x509_crt_init(&CA_cert);

		assert_tls(
			mbedtls_ctr_drbg_seed(
			&CTRDBG_context,
			mbedtls_entropy_func,
			&entropy_context,
			reinterpret_cast<const unsigned char*>(seed.c_str()),
			seed.length()
			)
		);

		//setup SSL/TLS
		memset(&SSL_config, 0, sizeof(mbedtls_ssl_config));
		assert_tls(mbedtls_ssl_config_defaults(&SSL_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));

		mbedtls_ssl_conf_rng(&SSL_config, mbedtls_entropy_func, &entropy_context);
		mbedtls_ssl_conf_dbg(&SSL_config, debug_fn, stdout);

		mbedtls_ssl_set_bio(&SSL_context, context_data, send_cb, recv_cb, recv_timeout_cb);
		mbedtls_ssl_set_timer_cb(&SSL_context, &timing_delay_context, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
	}

	tls_client::tls_client(mbedtls_ssl_send_t send_cb, mbedtls_ssl_recv_t recv_cb, mbedtls_ssl_recv_timeout_t recv_timeout_cb, void * context_data)
		: tls_client(send_cb, recv_cb, recv_timeout_cb, context_data, default_assert_tls){
	}

	tls_client::~tls_client(){
		mbedtls_x509_crt_free(&CA_cert);
		mbedtls_ssl_free(&SSL_context);
		mbedtls_ssl_config_free(&SSL_config);
		mbedtls_entropy_free(&entropy_context);
		mbedtls_ctr_drbg_free(&CTRDBG_context);
	}

	bool tls_client::setup(const string & hostname){
		this->hostname = hostname;
		mbedtls_debug_set_threshold(debug_level);

		mbedtls_ssl_conf_ca_chain(&SSL_config, &CA_cert, nullptr);

		assert_tls(mbedtls_ssl_setup(&SSL_context, &SSL_config));
		assert_tls(mbedtls_ssl_set_hostname(&SSL_context, hostname.c_str()));
		if (strict_crt){
			SSL_config.authmode = MBEDTLS_SSL_VERIFY_REQUIRED;
		}
		else{
			SSL_config.authmode = MBEDTLS_SSL_VERIFY_OPTIONAL;
		}
		return true;
	}

	int tls_client::handshake(){
		int rc = mbedtls_ssl_handshake(&SSL_context);
		return assert_tls(rc);
	}

	int tls_client::read(char * buffer, size_t length){
		return mbedtls_ssl_read(&SSL_context, reinterpret_cast<unsigned char*>(buffer), length);
	}

	int tls_client::write(const char * buffer, size_t length){
		return mbedtls_ssl_write(&SSL_context, reinterpret_cast<const unsigned char*>(buffer), length);
	}

	int tls_client::set_CA_chain(const char * buffer, size_t length){
		if ((length > 0) && buffer){
			int rc = assert_tls(mbedtls_x509_crt_parse(&CA_cert, reinterpret_cast<const unsigned char*>(buffer), length));
			mbedtls_ssl_conf_ca_chain(&SSL_config, &CA_cert, nullptr);
			strict_crt = true;
			return rc;
		}
		else{
			strict_crt = false;
			return 0;
		}
	}


	ztls_client_state::ztls_client_state(void * zmq_context, const char * endpoint_out, const char * endpoint_control){
		assert(endpoint_out != nullptr);

		this->zmq_context = zmq_context;
		own_zmq_context = false;
		this->endpoint_out = endpoint_out;

		tls_state = nullptr;
		input_buffer = new SimpleBuffer(ZTLS_INPUT_BUFFER_SIZE);
		connection_state = ztls_connection_state::ZTLS_DISCONNECTED;

		memset(&zmq_poll_in, 0, sizeof(zmq_pollitem_t));
		memset(&zmq_poll_out, 0, sizeof(zmq_pollitem_t));
		memset(&zmq_poll_control, 0, sizeof(zmq_pollitem_t));

		assert(zmq_socket_in = zmq_socket(zmq_context, ZMQ_STREAM));
		assert(zmq_socket_out = zmq_socket(zmq_context, ZMQ_PAIR));

		int linger = ZTLS_MAX_LINGER;
		assert(zmq_setsockopt(zmq_socket_in, ZMQ_LINGER, &linger, sizeof(linger)) == 0);
		assert(zmq_setsockopt(zmq_socket_out, ZMQ_LINGER, &linger, sizeof(linger)) == 0);

		if (endpoint_control){
			assert(zmq_socket_control = zmq_socket(zmq_context, ZMQ_PAIR));
			assert(zmq_setsockopt(zmq_socket_control, ZMQ_LINGER, &linger, sizeof(linger)) == 0);
			assert(zmq_bind(zmq_socket_control, endpoint_control) == 0);
			zmq_poll_control.socket = zmq_socket_control;
			zmq_poll_control.events = ZMQ_POLLIN;
		}
		else{
			zmq_socket_control = nullptr;
		}

		zmq_poll_in.socket = zmq_socket_in;
		zmq_poll_in.events = ZMQ_POLLIN;
		zmq_poll_out.socket = zmq_socket_out;
		zmq_poll_out.events = ZMQ_POLLIN;
	}

	ztls_client_state::ztls_client_state(const char * endpoint_out, const char * endpoint_control){
		ztls_client_state(zmq_ctx_new(), endpoint_out, endpoint_control);
		own_zmq_context = true;
	}

	ztls_client_state::~ztls_client_state(){
		if (tls_state){
			close();
		}
		
		if (zmq_socket_control){
			zmq_close(zmq_socket_control);
		}

		zmq_close(zmq_socket_out);
		zmq_close(zmq_socket_in);

		if (own_zmq_context){
			zmq_ctx_term(zmq_context);
		}
		delete input_buffer;
	}

	bool ztls_client_state::connect(const string & hostname, uint16_t port){
		if (tls_state){
			close();
		}

		const string endpoint = sprintf_ex("tcp://%s:%u", hostname.c_str(), port);

		assert(zmq_connect(zmq_socket_in, endpoint.c_str()) == 0);

		if (connection_state == ztls_connection_state::ZTLS_DISCONNECTED){
			if (process_state_change()){
				connection_state = ztls_connection_state::ZTLS_CONNECTED;
			}
		}

		if (connection_state == ztls_connection_state::ZTLS_CONNECTED){
			tls_state = new tls_client(send_cb, recv_cb, recv_timeout_cb, this, bind(&ztls_client_state::assert_tls, this, placeholders::_1));

			tls_state->setup(hostname);
			
			if (tls_state->handshake() != 0){
				close();
				return false;
			}{
				assert(zmq_bind(zmq_socket_out, endpoint_out.c_str()) == 0);
				transport_running = true;
				data_transport = thread([&](){
					while (transport_running){
						process_transport();
					}
				});
				connection_state = ztls_connection_state::ZTLS_READY;
				return true;
			}
		}
		else{
			return false;
		}
	}

	void ztls_client_state::close(){
		if (connection_state == ztls_connection_state::ZTLS_READY){
			transport_running = false;
			if (data_transport.joinable()){
				data_transport.join();
			}
		}
		if (connection_state != ztls_connection_state::ZTLS_DISCONNECTED){
			send_data_more(zmq_socket_in, client_id.c_str(), client_id.length());
			send_data(zmq_socket_in, nullptr, 0);
		}

		if (tls_state){
			delete tls_state;
			tls_state = nullptr;
		}
		connection_state = ztls_connection_state::ZTLS_DISCONNECTED;
	}

	inline bool ztls_client_state::dataOnInput(uint32_t t){
		zmq_poll_in.events = ZMQ_POLLIN;
		return (zmq_poll(&zmq_poll_in, 1, t) > 0);
	}

	bool ztls_client_state::process_state_change(){
		zmq_poll_in.events = ZMQ_POLLIN;
		int result = zmq_poll(&zmq_poll_in, 1, -1);
		if (result > 0){
			recv_data(zmq_poll_in.socket, [&](char *data, size_t len) -> int{
				if (client_id.length() <= 0){
					client_id = string(data, len);
				}
				return 0;
			});

			if (recv_data(zmq_poll_in.socket, [&](char *data, size_t len) -> int{
				if (len == 0){
					return 0;
				}
				else{
					return -1;
				}
			}) == 0){
				return true;
			}
			else{
				return false;
			}
		}
		else{
			return false;
		}
	}

	int ztls_client_state::send_cb(void * context_data, const unsigned char * data, size_t len){
		ztls_client_state * state = reinterpret_cast<ztls_client_state*>(context_data);
		if (state->connection_state & (ztls_connection_state::ZTLS_CONNECTED | ztls_connection_state::ZTLS_READY)){
			state->zmq_poll_in.events = ZMQ_POLLOUT;
			int result = zmq_poll(&state->zmq_poll_in, 1, 2000);

			if (result > 0){
				send_data_more(state->zmq_poll_in.socket, state->client_id.c_str(), state->client_id.length());
				return send_data_more(state->zmq_poll_in.socket, data, len);
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
		else{
			return EOF;
		}
	}

	int ztls_client_state::recv_timeout_cb(void * context_data, unsigned char * data, size_t len, uint32_t t){
		ztls_client_state * state = reinterpret_cast<ztls_client_state*>(context_data);

		if (state->connection_state & (ztls_connection_state::ZTLS_CONNECTED | ztls_connection_state::ZTLS_READY)){
			while (!state->input_buffer->hasEnough(len)){
				state->zmq_poll_in.events = ZMQ_POLLIN;
				//translate timeout value from mbedtls to ZeroMQ notation
				if (t == 0){
					t = -1;
				}
				int result = zmq_poll(&state->zmq_poll_in, 1, t);

				if (result > 0){
					recv_data(state->zmq_poll_in.socket, [&](char *data, size_t len) -> int{
						if (state->client_id.length() <= 0){
							state->client_id = string(data, len);
						}
						return 0;
					});

					int rc = recv_data(state->zmq_poll_in.socket, [&](char * data, size_t length) -> int{
						if (length > 0){
							return (state->input_buffer->push(reinterpret_cast<char*>(data), length)) ? 1 : -1;
						}
						else if (rc == 0){
							state->connection_state = ztls_connection_state::ZTLS_DISCONNECTED;
							return EOF;
						}
						else{
							return 0;
						}
					});

					//server connection state change
					if (rc == 0){
						return EOF;
					}
					else if (rc < 0){
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
		else{
			return EOF;
		}
	}

	inline int ztls_client_state::recv_cb(void * context_data, unsigned char * data, size_t len){
		return recv_timeout_cb(context_data, data, len, -1);
	}

	void ztls_client_state::process_transport(){
		zmq_poll_out.events = ZMQ_POLLIN | ZMQ_POLLOUT;

		int result = zmq_poll(&zmq_poll_out, 1, -1);
		if (result > 0){
			if (zmq_poll_out.revents & ZMQ_POLLIN){
				int rc = recv_data(zmq_poll_out.socket, [&](char * data, size_t length) -> int{
					int rc = 0;
					do {
						rc = tls_state->write(data, length);
					} while ((rc == MBEDTLS_ERR_SSL_WANT_READ) || (rc == MBEDTLS_ERR_SSL_WANT_WRITE));

					return rc;
				});
			}

			if (zmq_poll_out.revents & ZMQ_POLLOUT){
				if (dataOnInput(0))
				{
					int rc = 0;
					char buffer[ZTLS_INPUT_BUFFER_SIZE];

					do{
						rc = tls_state->read(buffer, ZTLS_INPUT_BUFFER_SIZE);
					} while ((rc == MBEDTLS_ERR_SSL_WANT_READ) || (rc == MBEDTLS_ERR_SSL_WANT_WRITE));

					if (rc > 0){
						send_data(zmq_poll_out.socket, buffer, rc);
					}
					else{
						if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY){
							return;
						}
					}
				}
			}
		}
		return;
	}

	bool ztls_client_state::set_CA(const char * buffer, size_t len){
		if (tls_state){
			return (tls_state->set_CA_chain(buffer, len) > 0);
		}
		else{
			return false;
		}
	}

	int ztls_client_state::assert_tls(int rc){
		if ((rc != 0) && (zmq_socket_control)){
			char errorMsg[ZTLS_ERROR_MESSAGE_SIZE];
			mbedtls_strerror(rc, errorMsg, ZTLS_ERROR_MESSAGE_SIZE);

			zmq_poll_control.events = ZMQ_POLLOUT;
			int result = zmq_poll(&zmq_poll_control, 1, -1);

			if (result >= 0 && (zmq_poll_control.revents & ZMQ_POLLOUT)){
				char data[] = "ERROR";
				send_data_more(zmq_poll_control.socket, data, strlen(data) + 1);
				send_data(zmq_poll_control.socket, errorMsg, strlen(errorMsg) + 1);
			}
		}
		return rc;
	}

}

