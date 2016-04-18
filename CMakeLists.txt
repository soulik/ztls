cmake_minimum_required (VERSION 3.1.0)
project (ztls)

list(APPEND CMAKE_MODULE_PATH "${luazmq_SOURCE_DIR}/cmake")

# Include zlib

add_subdirectory(dependencies/zlib)
include_directories(dependencies/zlib)

set_target_properties(zlib
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
)

set_target_properties(zlibstatic
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
)

# Include mbedtls

set(ZLIB_LIBRARY $<TARGET_LINKER_FILE:zlib>)
set(ZLIB_INCLUDE_DIR ${luambedtls_SOURCE_DIR}/dependencies/zlib)

# add_subdirectory(dependencies/mbedtls)
# include_directories(dependencies/mbedtls/include)
add_subdirectory(dependencies/mbedtls)
include_directories(dependencies/mbedtls/include)

if (USE_STATIC_MBEDTLS_LIBRARY AND USE_SHARED_MBEDTLS_LIBRARY)
	set(mbedtls_static_library "mbedtls_static")
	set(mbedcrypto_static_library "mbedcrypto_static")
	set(mbedx509_static_library "mbedx509_static")
else()
	set(mbedtls_static_library "mbedtls")
	set(mbedcrypto_static_library "mbedcrypto")
	set(mbedx509_static_library "mbedx509")
endif()

set_target_properties(${mbedtls_static_library}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
    DEFINE_SYMBOL "MBEDTLS_EXPORTS"
)

set_target_properties(${mbedcrypto_static_library}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
    DEFINE_SYMBOL "MBEDTLS_EXPORTS"
)

set_target_properties(${mbedx509_static_library}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
    DEFINE_SYMBOL "MBEDTLS_EXPORTS"
)

if (UNIX)
	set_target_properties(${mbedtls_static_library}
	    PROPERTIES
	    COMPILE_FLAGS "-fPIC"
	)
	set_target_properties(${mbedcrypto_static_library}
	    PROPERTIES
	    COMPILE_FLAGS "-fPIC"
	)
	set_target_properties(${mbedx509_static_library}
	    PROPERTIES
	    COMPILE_FLAGS "-fPIC"
	)
endif()

set(ztls_USE_LIBSODIUM ON CACHE BOOL "Build and use internal copy of libsodium")

if (ztls_USE_LIBSODIUM)

	# Include libsodium

	add_subdirectory(dependencies/libsodium)
	include_directories(dependencies/libsodium/src/libsodium/include)
	include_directories(dependencies/libsodium/src/libsodium/include/sodium)
	include_directories("${CMAKE_BINARY_DIR}/dependencies/libsodium/src/libsodium/include")
	add_definitions(-DSODIUM_DLL_EXPORT)

	set_target_properties(libsodium
	    PROPERTIES
	    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
	    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
	    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
	)
	
	set(SODIUM_FOUND 1)
	set(SODIUM_LIBRARY $<TARGET_LINKER_FILE:libsodium>)
	set(SODIUM_LIBRARIES $<TARGET_LINKER_FILE:libsodium>)
endif()

# Include libzmq

set(ZMQ_BUILD_TESTS OFF CACHE BOOL "Build the tests for ZeroMQ")
add_subdirectory(dependencies/libzmq)
include_directories(dependencies/libzmq/include)

set_target_properties(libzmq
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
)

if (ztls_USE_LIBSODIUM)
	add_dependencies(libzmq libsodium)
	target_compile_definitions(libzmq PRIVATE -DHAVE_LIBSODIUM)
endif()

add_subdirectory(src)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY build)
set_target_properties(ztls PROPERTIES PREFIX "")

add_subdirectory(tests)
