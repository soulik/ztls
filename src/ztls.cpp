#include "common.hpp"
#include "ztls.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509.h>
#include <mbedtls/timing.h>

#include <cassert>
#include <string>
#include <thread>

using namespace std;

namespace ztls {
	struct ztls_state_private {
		mbedtls_entropy_context entropy_context;
		mbedtls_ctr_drbg_context CTRDBG_context;
		mbedtls_ssl_context SSL_context;
		mbedtls_x509_crt CA_cert;
		mbedtls_timing_delay_context timing_delay_context;
		mbedtls_ssl_config SSL_config;
		string seed;

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
		bool running;
	};

	struct ztls_state_public {
		void * zmq_context;
		void * zmq_socket_control;
		zmq_pollitem_t zmq_poll_control;
		thread worker;
	};

	int send_cb(void * context_data, const unsigned char * data, size_t len){
		ztls_state_private * state = reinterpret_cast<ztls_state_private*>(context_data);

		state->zmq_poll_in.events = ZMQ_POLLOUT;
		int result = zmq_poll(&state->zmq_poll_in, 1, -1);

		if (result >= 0){
			zmq_msg_t msg;
			zmq_msg_init_data(&msg, const_cast<unsigned char *>(data), len, nullptr, nullptr);
			zmq_msg_send(&msg, &state->zmq_socket_in, 0);
			zmq_msg_close(&msg);
			return len;
		}
		else{
			return MBEDTLS_ERR_SSL_TIMEOUT;
		}
	}

	int recv_cb(void * context_data, unsigned char * data, size_t len){
		ztls_state_private * state = reinterpret_cast<ztls_state_private*>(context_data);

		state->zmq_poll_in.events = ZMQ_POLLIN;
		int result = zmq_poll(&state->zmq_poll_in, 1, -1);

		if (result >= 0){
			zmq_msg_t msg;
			zmq_msg_init_size(&msg, len);
			zmq_msg_recv(&msg, &state->zmq_socket_in, 0);
			size_t recvLength = zmq_msg_size(&msg);
			size_t usableLength = (recvLength > len) ? len : recvLength;
			memcpy(data, zmq_msg_data(&msg), usableLength);
			zmq_msg_close(&msg);
			return usableLength;
		}
		else{
			return MBEDTLS_ERR_SSL_TIMEOUT;
		}
	}

	int recv_timeout_cb(void * context_data, unsigned char * data, size_t len, uint32_t t){
		ztls_state_private * state = reinterpret_cast<ztls_state_private*>(context_data);

		state->zmq_poll_in.events = ZMQ_POLLIN;
		int result = zmq_poll(&state->zmq_poll_in, 1, t);

		if (result >= 0){
			zmq_msg_t msg;

			zmq_msg_init_size(&msg, len);
			zmq_msg_recv(&msg, &state->zmq_socket_in, 0);
			size_t recvLength = zmq_msg_size(&msg);
			size_t usableLength = (recvLength > len) ? len : recvLength;
			memcpy(data, zmq_msg_data(&msg), usableLength);
			zmq_msg_close(&msg);
			return usableLength;
		}
		else{
			return MBEDTLS_ERR_SSL_TIMEOUT;
		}
	}

	void ztls_zmq_init(ztls_state_private * state){
		state->zmq_socket_in = zmq_socket(state->zmq_context, ZMQ_PAIR);
		state->zmq_socket_out = zmq_socket(state->zmq_context, ZMQ_PAIR);
		zmq_bind(state->zmq_socket_in, state->endpoint_in.c_str());
		zmq_bind(state->zmq_socket_out, state->endpoint_out.c_str());
		zmq_bind(state->zmq_socket_control, state->endpoint_control.c_str());

		state->zmq_poll_in.socket = state->zmq_socket_in;
		state->zmq_poll_in.events = ZMQ_POLLIN;
		state->zmq_poll_out.socket = state->zmq_socket_out;
		state->zmq_poll_out.events = ZMQ_POLLIN;
		state->zmq_poll_control.socket = state->zmq_socket_control;
		state->zmq_poll_control.events = ZMQ_POLLIN;
	}

	void ztls_zmq_destroy(ztls_state_private * state){
		zmq_close(state->zmq_socket_control);
		zmq_close(state->zmq_socket_out);
		zmq_close(state->zmq_socket_in);
	}

	bool ztls_process_internal(ztls_state_private * state){
		int result = zmq_poll(&state->zmq_poll_control, 1, 0);

		if (result > 0){
			zmq_msg_t msgControl;
			zmq_msg_init(&msgControl);
			zmq_msg_recv(&msgControl, &state->zmq_socket_control, 0);
			char * data = reinterpret_cast<char*>(zmq_msg_data(&msgControl));
			size_t length = zmq_msg_size(&msgControl);
			if (strncmp(data, "QUIT", (length < 16) ? length : 16) == 0){
				state->running = false;
			}
			zmq_msg_close(&msgControl);
		}

		if (state->running){
			state->zmq_poll_in.events = ZMQ_POLLIN | ZMQ_POLLOUT;
			result = zmq_poll(&state->zmq_poll_out, 1, -1);

			if (result >= 0){
				zmq_msg_t msgIn;
				zmq_msg_t msgOut;

				if (state->zmq_poll_out.revents & ZMQ_POLLIN){
					zmq_msg_init(&msgIn);
					zmq_msg_recv(&msgIn, &state->zmq_socket_out, 0);

					int rc = 0;
					do {
						rc = mbedtls_ssl_write(&state->SSL_context, reinterpret_cast<unsigned char *>(zmq_msg_data(&msgIn)), zmq_msg_size(&msgIn));
					} while ((rc != MBEDTLS_ERR_SSL_WANT_READ) && (rc != MBEDTLS_ERR_SSL_WANT_WRITE));

					zmq_msg_close(&msgIn);
				}

				if (state->zmq_poll_out.revents & ZMQ_POLLOUT){
					size_t recvLength = mbedtls_ssl_get_bytes_avail(&state->SSL_context);
					if (recvLength > 0){
						zmq_msg_init_size(&msgOut, recvLength);

						int rc = 0;

						do{
							rc = mbedtls_ssl_read(&state->SSL_context, reinterpret_cast<unsigned char *>(zmq_msg_data(&msgOut)), recvLength);
						} while ((rc != MBEDTLS_ERR_SSL_WANT_READ) && (rc != MBEDTLS_ERR_SSL_WANT_WRITE));

						if (rc > 0){
							zmq_msg_send(&msgOut, &state->zmq_socket_out, 0);
						}
						else{
							if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY){
								state->running = false;
							}
						}

						zmq_msg_close(&msgOut);
					}
				}
			}
			return true;
		}
		else{
			return false;
		}
	}

	ztls_state_private * ztls_client_init_internal(void * zmq_context, const string endpoint_in, const string endpoint_out, const string endpoint_control, const string hostname){
		assert(zmq_context != nullptr);
		ztls_state_private * state = new ztls_state_private;

		mbedtls_ctr_drbg_init(&state->CTRDBG_context);
		mbedtls_entropy_init(&state->entropy_context);
		mbedtls_ssl_config_init(&state->SSL_config);
		mbedtls_ssl_init(&state->SSL_context);
		mbedtls_x509_crt_init(&state->CA_cert);

		state->seed = "ztls_test";
		state->endpoint_in = endpoint_in;
		state->endpoint_out = endpoint_out;
		state->endpoint_control = endpoint_control;

		state->running = true;

		state->zmq_context = zmq_context;
		ztls_zmq_init(state);

		mbedtls_ctr_drbg_seed(&state->CTRDBG_context, mbedtls_entropy_func, &state->entropy_context, reinterpret_cast<const unsigned char*>(state->seed.c_str()), state->seed.length());

		memset(&state->SSL_config, 0, sizeof(mbedtls_ssl_config));
		mbedtls_ssl_config_defaults(&state->SSL_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
		state->SSL_config.authmode = MBEDTLS_SSL_VERIFY_OPTIONAL;
		mbedtls_ssl_conf_ca_chain(&state->SSL_config, &state->CA_cert, nullptr);
		mbedtls_ssl_conf_rng(&state->SSL_config, mbedtls_entropy_func, &state->entropy_context);

		mbedtls_ssl_setup(&state->SSL_context, &state->SSL_config);
		mbedtls_ssl_set_hostname(&state->SSL_context, hostname.c_str());

		mbedtls_ssl_set_bio(&state->SSL_context, state, send_cb, recv_cb, recv_timeout_cb);
		mbedtls_ssl_set_timer_cb(&state->SSL_context, &state->timing_delay_context, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

		mbedtls_ssl_handshake(&state->SSL_context);

		return state;
	}

	void ztls_client_destroy_internal(ztls_state_private * state){
		mbedtls_ssl_close_notify(&state->SSL_context);

		ztls_zmq_destroy(state);

		mbedtls_x509_crt_free(&state->CA_cert);
		mbedtls_ssl_free(&state->SSL_context);
		mbedtls_ssl_config_free(&state->SSL_config);
		mbedtls_entropy_free(&state->entropy_context);
		mbedtls_ctr_drbg_free(&state->CTRDBG_context);

		delete state;
	}

	void * ztls_client_init(const char * endpoint_in, const char * endpoint_out, const char * endpoint_control, const char * hostname){
		assert(endpoint_in != nullptr);
		assert(endpoint_out != nullptr);
		assert(endpoint_control != nullptr);
		assert(hostname != nullptr);

		ztls_state_public * state = new ztls_state_public;
		state->zmq_context = zmq_ctx_new();
		state->zmq_socket_control = zmq_socket(state->zmq_context, ZMQ_PAIR);
		state->zmq_poll_control.socket = state->zmq_socket_control;
		state->zmq_poll_control.events = ZMQ_POLLOUT;

		zmq_connect(state->zmq_socket_control, endpoint_control);

		state->worker = std::thread([&](void * zmq_context, const string endpoint_in, const string endpoint_out, const string endpoint_control, const string hostname){
			ztls_state_private * private_state = ztls_client_init_internal(zmq_context, endpoint_in, endpoint_out, endpoint_control, hostname);

			bool result = true;
			do {
				result = ztls_process_internal(private_state);
			} while (result);

			ztls_client_destroy_internal(private_state);
		}, state->zmq_context, endpoint_in, endpoint_out, endpoint_control, hostname);
		return state;
	}

	bool ztls_client_destroy(void * _state){
		ztls_state_public * state = reinterpret_cast<ztls_state_public*>(_state);
		
		int result = zmq_poll(&state->zmq_poll_control, 1, -1);

		if (result >= 0){
			char data[] = "STOP";
			zmq_msg_t msg;
			zmq_msg_init_data(&msg, data, 4, nullptr, nullptr);
			zmq_msg_send(&msg, &state->zmq_socket_control, 0);
			zmq_msg_close(&msg);

			state->worker.join();
			zmq_ctx_destroy(state->zmq_context);
			return true;
		}else{
			return false;
		}
	}

};