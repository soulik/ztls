#ifndef ZTLS_PRIVATE_H
#define ZTLS_PRIVATE_H

#include <zmq.h>

#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509.h>
#include <mbedtls/timing.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

using namespace std;

#ifndef _MSC_VER

#define _alloca	alloca

#endif

#define ZTLS_INPUT_BUFFER_SIZE 8192*4
#define ZTLS_ERROR_MESSAGE_SIZE 4096
#define ZTLS_MAX_COMMAND_BUFFER_SIZE 32
#define ZTLS_MAX_LINGER 2000

namespace ztls {
	inline string sprintf_ex(const string & fmt, ...){
		va_list args;
		va_start(args, fmt);
		vector<char> buf(vsnprintf(nullptr, 0, fmt.c_str(), args));
		vsnprintf(buf.data(), buf.size(), fmt.c_str(), args);
		va_end(args);
		return string(buf.data(), buf.size());
	}

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

		size_t available(){
			return pos;
		}
	};

	class tls_client {
	private:
		mbedtls_entropy_context entropy_context;
		mbedtls_ctr_drbg_context CTRDBG_context;
		mbedtls_ssl_context SSL_context;
		mbedtls_x509_crt CA_cert;
		mbedtls_timing_delay_context timing_delay_context;
		mbedtls_ssl_config SSL_config;
		string seed;
		string hostname;
		static void debug_fn(void *ctx, int level, const char *file, int line, const char *str);
		function<int (int rc)> assert_tls;
		static inline int default_assert_tls(int rc){
			assert(rc == 0);
			return rc;
		}

		bool strict_crt;
	public:
		tls_client(mbedtls_ssl_send_t send_cb, mbedtls_ssl_recv_t recv_cb, mbedtls_ssl_recv_timeout_t recv_timeout_cb, void * context_data, int debug_level = 0);
		tls_client(mbedtls_ssl_send_t send_cb, mbedtls_ssl_recv_t recv_cb, mbedtls_ssl_recv_timeout_t recv_timeout_cb, void * context_data, int debug_level, function<int(int rc)> assert_tls_fn);
		~tls_client();
		int read(char * buffer, size_t length);
		int write(const char * buffer, size_t length);
		int set_CA_chain(const char * buffer, size_t length);
		bool setup(const string & hostname);
		size_t get_bytes_avail();
		void close();

		inline int handshake();
		int debug_level;
	};

	enum ztls_connection_state {
		ZTLS_DISCONNECTED = 0,
		ZTLS_CONNECTED = 1,
		ZTLS_READY = 2,
	};

	class ztls_client_state {
	private:
		//tls part
		tls_client * tls_state;

		//ZeroMQ part
		void * zmq_context;
		void * zmq_context_tls;
		void * zmq_socket_in;
		void * zmq_socket_out;
		void * zmq_socket_control;
		zmq_pollitem_t zmq_poll_in;
		zmq_pollitem_t zmq_poll_out;
		zmq_pollitem_t zmq_poll_control;

		zmq_pollitem_t transport_poll_in[2];
		zmq_pollitem_t transport_poll_out[2];

		string client_id;

		SimpleBuffer * input_buffer;
		bool own_zmq_context;
		atomic<ztls_connection_state> connection_state;
		string endpoint_out;
		thread data_transport;
		atomic<bool> transport_running;

		bool dataOnInput(uint32_t t);
		static int send_cb(void * context_data, const unsigned char * data, size_t len);
		static int recv_cb(void * context_data, unsigned char * data, size_t len);
		static int recv_timeout_cb(void * context_data, unsigned char * data, size_t len, uint32_t t);

		bool process_state_change();

		void process_transport();
		int assert_tls(int rc);
	public:
		ztls_client_state(const char * endpoint_out, const char * endpoint_control = nullptr);
		ztls_client_state(void * zmq_context, const char * endpoint_out, const char * endpoint_control= nullptr);
		~ztls_client_state();

		bool connect(const string & hostname, uint16_t port, int debug_level = 0);
		void close();
		void tls_close();
		bool set_CA(const char * buffer, size_t len);
	};

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
		if (rc < 0){
			cout << "zmq_msg_send: " << zmq_strerror(zmq_errno());
		}
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
};

#endif