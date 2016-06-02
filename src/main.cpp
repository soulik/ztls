#include "common.hpp"
#include "ztls.hpp"
#include "ztls_private.hpp"
#include <iostream>
using namespace ztls;

void * ztls_client_new(const char * endpoint_out, const char * endpoint_control){
	assert(endpoint_out);
	return new ztls_client_state(endpoint_out, endpoint_control);
}

void * ztls_client_new_with_ctx(void * zmq_context, const char * endpoint_out, const char * endpoint_control){
	assert(zmq_context);
	assert(endpoint_out);
	return new ztls_client_state(zmq_context, endpoint_out, endpoint_control);
}

bool ztls_client_connect(void * _state, const char * hostname, uint16_t port, int debug_level){
	assert(_state);
	assert(hostname);
	assert(port > 0);
	ztls_client_state * state = reinterpret_cast<ztls_client_state*>(_state);
	return state->connect(hostname, port, debug_level);
}

bool ztls_client_close(void * _state){
	assert(_state);
	ztls_client_state * state = reinterpret_cast<ztls_client_state*>(_state);
	state->close();
	return true;
}

bool ztls_client_destroy(void * _state){
	assert(_state);
	ztls_client_state * state = reinterpret_cast<ztls_client_state*>(_state);
	delete state;
	return true;
}

bool ztls_client_CA_chain(void * _state, const char * buffer, size_t len){
	assert(_state);
	assert(buffer);
	ztls_client_state * state = reinterpret_cast<ztls_client_state*>(_state);
	return state->set_CA(buffer, len);
}


