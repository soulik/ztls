#ifndef ZTLS_H
#define ZTLS_H

#include <stdint.h>

#if (BUILDING_ZTLS || ztls_EXPORTS) && HAVE_VISIBILITY
#define ZTLS_DLL_EXPORTED __attribute__((visibility("default")))
#elif (BUILDING_ZTLS || ztls_EXPORTS) && defined _MSC_VER
#define ZTLS_DLL_EXPORTED __declspec(dllexport)
#elif defined _MSC_VER
#define ZTLS_DLL_EXPORTED __declspec(dllimport)
#else
#define ZTLS_DLL_EXPORTED
#endif

extern "C" ZTLS_DLL_EXPORTED  void * ztls_client_new(const char * endpoint_out, const char * endpoint_control = nullptr);
extern "C" ZTLS_DLL_EXPORTED  void * ztls_client_new_with_ctx(void * zmq_context, const char * endpoint_out, const char * endpoint_control = nullptr);
extern "C" ZTLS_DLL_EXPORTED  bool ztls_client_CA_chain(void * state, const char * buffer, size_t len);
extern "C" ZTLS_DLL_EXPORTED  bool ztls_client_connect(void * state, const char * hostname, uint16_t port, int debug_level = 0);
extern "C" ZTLS_DLL_EXPORTED  bool ztls_client_close(void * state);
extern "C" ZTLS_DLL_EXPORTED  bool ztls_client_destroy(void * state);

#endif