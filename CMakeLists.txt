cmake_minimum_required(VERSION 3.10)
project(libpaseto
	VERSION 1.0
	LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-g -Wall -Wextra -Wno-unused-parameter -Wno-unused-result -Werror)

# Default is to use C++ 17
set(CMAKE_CXX_STANDARD 17 CACHE STRING "Default C++ standard")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ensure --std=c++xx instead of --std=g++xx
set(CMAKE_CXX_EXTENSIONS OFF)
add_definitions(-Wno-deprecated)

# ----------------------------------------------------------------------------
# ASAN config
# ----------------------------------------------------------------------------
function(append value)
  foreach(variable ${ARGN})
    set(${variable}
        "${${variable}} ${value}"
        PARENT_SCOPE)
  endforeach(variable)
endfunction()

if (WITH_ASAN STREQUAL "1")
    append("-Og -g" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-fsanitize=address" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-fsanitize-address-use-after-scope" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-fno-omit-frame-pointer" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-fno-optimize-sibling-calls" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
endif ()



# ----------------------------------------------------------------------------
# External dependencies
# ----------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
include_directories(${SODIUM_INCLUDE_DIRS})

include(FetchContent)


FetchContent_Declare(json URL
	https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz)
FetchContent_MakeAvailable(json)


FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.0.1 # or a later release
)
FetchContent_MakeAvailable(Catch2)


FetchContent_Declare(
	fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 		 9.1.0
)
FetchContent_MakeAvailable(fmt)


set(CRYPTOPP_INSTALL OFF)
set(CRYPTOPP_BUILD_TESTING OFF)
FetchContent_Declare(
	cryptopp
  GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake
  GIT_TAG 		 CRYPTOPP_8_7_0
)
FetchContent_MakeAvailable(cryptopp)


include_directories(include cryptopp_pem)
set(PASETO_SOURCES
	cryptopp_pem/pem.h
	cryptopp_pem/pem_common.cpp
	cryptopp_pem/pem_common.h
	cryptopp_pem/pem_read.cpp
	cryptopp_pem/pem_write.cpp
	src/paseto_v2_local.c
	src/paseto_v2_public.c
	src/paseto_v3_local.cpp
	src/paseto_v3_public.cpp
	src/paseto_v4_local.c
	src/paseto_v4_public.c
	src/paseto.c
	src/helpers.c
	src/helpers.h
	src/helpers.cpp
	include/helpers.hpp
	include/paseto.hpp
	include/paserk.h
	include/paseto.h)

configure_file("paseto.pc.in" "paseto.pc" @ONLY)

# shared library build
add_library(paseto SHARED ${PASETO_SOURCES})
target_link_libraries(paseto
	${SODIUM_LIBRARIES}
	cryptopp::cryptopp
	)
install(TARGETS paseto
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
install(FILES
	include/paseto.h
	include/paseto.hpp
	include/paserk.h
	include/helpers.hpp
	DESTINATION include)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/paseto.pc"
	DESTINATION lib/pkgconfig)

# test executable
add_executable(pasetotest
	test/main.c
	test/helpers.h
	test/helpers.c
	test/test.h
	test/test.c
	test/v2vectors.h
	test/v2vectors.c
	test/v2publicvectors.c)
target_compile_definitions(pasetotest PRIVATE _POSIX_C_SOURCE=200809L)
target_link_libraries(pasetotest
	${SODIUM_LIBRARIES}
	cryptopp::cryptopp
	paseto)
add_custom_command(TARGET pasetotest POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E make_directory
	$<TARGET_FILE_DIR:pasetotest>/test
	COMMAND ${CMAKE_COMMAND} -E copy
	${CMAKE_CURRENT_SOURCE_DIR}/test/v2vectors.csv
	${CMAKE_CURRENT_SOURCE_DIR}/test/v2publicvectors.csv
	$<TARGET_FILE_DIR:pasetotest>/test)

add_executable(pasetocpptests
	test/helpers.h
	test/helpers.c
	test/test.cpp
	test/test_paseto_v2local.cpp
	test/test_paserk_v2local.cpp
	test/test_paseto_v2public.cpp
	test/test_paserk_v2public.cpp
	test/test_paseto_v2secret.cpp
	test/test_paserk_v2secret.cpp
	test/test_paseto_v3local.cpp
	test/test_paserk_v3local.cpp
	test/test_paseto_v3public.cpp
	test/test_paserk_v3public.cpp
	test/test_paseto_v3secret.cpp
	test/test_paserk_v3secret.cpp
	)
target_link_libraries(pasetocpptests
	PRIVATE
	paseto
	${SODIUM_LIBRARIES}
	cryptopp::cryptopp
	Catch2::Catch2WithMain
	fmt::fmt-header-only
	nlohmann_json::nlohmann_json)

add_executable(pasetojsontest
	test/helpers.h
	test/helpers.c
	test/jsontest.cpp)
target_compile_definitions(pasetojsontest PRIVATE)
target_link_libraries(pasetojsontest
	PUBLIC
	paseto
	${SODIUM_LIBRARIES}
	cryptopp::cryptopp
	fmt::fmt-header-only
	nlohmann_json::nlohmann_json)
add_custom_command(TARGET pasetojsontest POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E make_directory
	$<TARGET_FILE_DIR:pasetotest>/test
	COMMAND ${CMAKE_COMMAND} -E copy
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/v2.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/v3.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/v4.json
	$<TARGET_FILE_DIR:pasetotest>/test)

add_executable(paserkjsontest
	test/helpers.h
	test/helpers.c
	test/paserkjsontest.cpp)
target_compile_definitions(paserkjsontest PRIVATE)
target_link_libraries(paserkjsontest
	PUBLIC
	paseto
	${SODIUM_LIBRARIES}
	cryptopp::cryptopp
	fmt::fmt-header-only
	nlohmann_json::nlohmann_json)
add_custom_command(TARGET paserkjsontest POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E make_directory
	$<TARGET_FILE_DIR:pasetotest>/test/paserk
	COMMAND ${CMAKE_COMMAND} -E copy
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.lid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.local-pw.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.local-wrap.pie.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.local.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.pid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.public.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.seal.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.secret-pw.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.secret-wrap.pie.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.secret.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k1.sid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.lid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.local-pw.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.local-wrap.pie.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.local.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.pid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.public.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.seal.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.secret-pw.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.secret-wrap.pie.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.secret.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k2.sid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.lid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.local-pw.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.local-wrap.pie.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.local.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.pid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.public.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.seal.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.secret-pw.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.secret-wrap.pie.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.secret.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k3.sid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.lid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.local-pw.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.local-wrap.pie.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.local.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.pid.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.public.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.seal.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.secret-pw.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.secret-wrap.pie.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.secret.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/test-vectors/PASERK/k4.sid.json
	$<TARGET_FILE_DIR:pasetotest>/test/paserk)


include(CTest)
include(Catch)
catch_discover_tests(pasetocpptests)

# examples
set(EXAMPLES example paseto-v2-local-encrypt paseto-v2-local-decrypt)
foreach(EXAMPLE ${EXAMPLES})
	add_executable(${EXAMPLE} examples/${EXAMPLE}.c)
	target_link_libraries(${EXAMPLE}
		${SODIUM_LIBRARIES}
		cryptopp::cryptopp
		paseto)
endforeach()


set(CPPEXAMPLES cppexample cppexample2)
foreach(CPPEXAMPLE ${CPPEXAMPLES})
	add_executable(${CPPEXAMPLE} examples/${CPPEXAMPLE}.cpp)
	target_link_libraries(${CPPEXAMPLE}
		paseto
		${SODIUM_LIBRARIES}
		fmt::fmt-header-only)
endforeach()
