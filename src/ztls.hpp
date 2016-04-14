#ifndef ZTLS_H
#define ZTLS_H

namespace ztls {
	ZTLS_DLL_EXPORTED void * ztls_client_init(const char * endpoint_in, const char * endpoint_out, const char * endpoint_control, const char * hostname);
	ZTLS_DLL_EXPORTED bool ztls_client_destroy(void * state);
};

#endif