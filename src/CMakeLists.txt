set(ztls_src
	main.cpp
	common.hpp
	ztls_client.cpp
	ztls.hpp
	ztls_private.hpp
)

set(ztls_sources
	${ztls_src}
)

include_directories(./)

set(ztls_version_script ztls.version)

IF(UNIX)
    IF(CMAKE_COMPILER_IS_GNUCC)
         SET(CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${CMAKE_CXX_COMPILE_OPTIONS_VISIBILITY}hidden -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/${ztls_version_script}")
    ENDIF(CMAKE_COMPILER_IS_GNUCC)

    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wmissing-declarations")
ENDIF(UNIX)

add_library(ztls SHARED
	${ztls_sources}
)

add_definitions(-D_CRT_SECURE_NO_WARNINGS)

set_property(TARGET ztls PROPERTY CXX_STANDARD 11)
set_property(TARGET ztls PROPERTY CXX_STANDARD_REQUIRED ON)

set_target_properties(ztls
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_SYSTEM_PROCESSOR}/bin"
)

set(ztls_LIBRARIES
	${mbedtls_static_library}
	${mbedcrypto_static_library}
	${mbedx509_static_library}
)

target_link_libraries (ztls
	libzmq
	libsodium
	${ztls_LIBRARIES}
	${LUA_LIBRARY}
)
