# ztls
ZeroMQ TLS proxy with mbedtls library

This project allows you to interconnect ZeroMQ network stack with SSL/TLS encrypted services.

## Architecture

All ztls endpoint use PAIR socket type. Keep in mind that ztls core runs in its own thread.

* Input endpoint - usually connected to STREAM socket type - e.g.: HTTPS, IMAPs, POP3s service
* Output endpoint - used to get/send data from/to the service
* Control endpoint (hidden at the moment) - used to manage proxy

## API
* Initializers - return ztls context object pointer

``void * ztls_client_init(const char * endpoint_in, const char * endpoint_out);``

``void * ztls_client_init_with_ctx(void * zmq_context, const char * endpoint_in, const char * endpoint_out);``

* Set SSL/TLS connection host

``bool ztls_client_connect(void * state, const char * hostname, char * error_message = nullptr, size_t max_error_message_length = 0);``

* Send client initiated close command over SSL/TLS

``bool ztls_client_close(void * state, char * error_message = nullptr, size_t max_error_message_length = 0);``

* Destroy ztls context

``bool ztls_client_destroy(void * state);``

## Examples

See http_client.cpp sample in tests/ directory.

## Authors
* Mário Kašuba <soulik42@gmail.com>

## Copying
Copyright 2016 Mário Kašuba
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
