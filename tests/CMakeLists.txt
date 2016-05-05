cmake_minimum_required (VERSION 3.1.0)
project (http_client)

set(http_client_src
	http_client.cpp
)

include_directories(../src)

add_executable(http_client
	${http_client_src}
)

set_target_properties(http_client
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
)

target_link_libraries (http_client
	ztls
)
