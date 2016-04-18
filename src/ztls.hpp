#ifndef ZTLS_H
#define ZTLS_H

#if (BUILDING_ZTLS || ztls_EXPORTS) && HAVE_VISIBILITY
#define ZTLS_DLL_EXPORTED __attribute__((visibility("default")))
#elif (BUILDING_ZTLS || ztls_EXPORTS) && defined _MSC_VER
#define ZTLS_DLL_EXPORTED __declspec(dllexport)
#elif defined _MSC_VER
#define ZTLS_DLL_EXPORTED __declspec(dllimport)
#else
#define ZTLS_DLL_EXPORTED
#endif

extern "C" ZTLS_DLL_EXPORTED  void * ztls_client_init(const char * endpoint_in, const char * endpoint_out);
extern "C" ZTLS_DLL_EXPORTED  void * ztls_client_init_with_ctx(void * zmq_context, const char * endpoint_in, const char * endpoint_out);
extern "C" ZTLS_DLL_EXPORTED  bool ztls_client_connect(void * state, const char * hostname, char * error_message = nullptr, size_t max_error_message_length = 0);
extern "C" ZTLS_DLL_EXPORTED  bool ztls_client_close(void * state, char * error_message = nullptr, size_t max_error_message_length = 0);
extern "C" ZTLS_DLL_EXPORTED  bool ztls_client_destroy(void * state);

#endif