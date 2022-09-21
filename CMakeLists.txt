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

#if (WITH_ASAN STREQUAL "1")
    append("-O1 -g" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-fsanitize=address" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-fsanitize-address-use-after-scope" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-fno-omit-frame-pointer" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    append("-fno-optimize-sibling-calls" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
#endif ()



find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
include_directories(${SODIUM_INCLUDE_DIRS})

include_directories(include)
set(PASETO_SOURCES
	src/paseto_v2_local.c
	src/paseto_v2_public.c
	src/paseto_v3_local.c
	src/paseto_v3_public.c
	src/paseto.c
	src/helpers.c
	src/helpers.h
	include/paseto.h)

configure_file("paseto.pc.in" "paseto.pc" @ONLY)


# shared library build
add_library(paseto SHARED ${PASETO_SOURCES})
target_link_libraries(paseto ${SODIUM_LIBRARIES})
install(TARGETS paseto
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
install(FILES
	include/paseto.h
	include/paseto2.hpp
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
target_link_libraries(pasetotest ${SODIUM_LIBRARIES} paseto)
add_custom_command(TARGET pasetotest POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E make_directory
	$<TARGET_FILE_DIR:pasetotest>/test
	COMMAND ${CMAKE_COMMAND} -E copy
	${CMAKE_CURRENT_SOURCE_DIR}/test/v2vectors.csv
	${CMAKE_CURRENT_SOURCE_DIR}/test/v2publicvectors.csv
	$<TARGET_FILE_DIR:pasetotest>/test)

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

FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 		 9.1.0
)
FetchContent_MakeAvailable(fmt)

add_executable(pasetocpptests
	test/helpers.h
	test/helpers.c
	test/test.cpp)
target_link_libraries(pasetocpptests
	PRIVATE
	paseto
	${SODIUM_LIBRARIES}
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
	fmt::fmt-header-only
	nlohmann_json::nlohmann_json)
add_custom_command(TARGET pasetojsontest POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E make_directory
	$<TARGET_FILE_DIR:pasetotest>/test
	COMMAND ${CMAKE_COMMAND} -E copy
	${CMAKE_CURRENT_SOURCE_DIR}/test/v2.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/v3.json
	${CMAKE_CURRENT_SOURCE_DIR}/test/v4.json
	$<TARGET_FILE_DIR:pasetotest>/test)

include(CTest)
include(Catch)
catch_discover_tests(pasetocpptests)

# examples
set(EXAMPLES example paseto-v2-local-encrypt paseto-v2-local-decrypt)
foreach(EXAMPLE ${EXAMPLES})
	add_executable(${EXAMPLE} examples/${EXAMPLE}.c)
	target_link_libraries(${EXAMPLE} ${SODIUM_LIBRARIES} paseto)
endforeach()

add_executable(cppexample examples/example.cpp)
target_link_libraries(cppexample
	paseto
	${SODIUM_LIBRARIES}
	fmt::fmt-header-only)

message(STATUS "CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER: ${CMAKE_CXX_COMPILER}")
message(STATUS "CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_C_LINK_FLAGS: ${CMAKE_C_LINK_FLAGS}")
