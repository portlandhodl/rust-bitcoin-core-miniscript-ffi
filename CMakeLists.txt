cmake_minimum_required(VERSION 3.16)
project(miniscript_wrapper VERSION 0.2.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(BUILD_SHARED_LIBS "Build shared library" OFF)
option(MINISCRIPT_WRAPPER_TESTS "Build tests" OFF)

set(BITCOIN_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/bitcoin/src"
    CACHE PATH "Path to Bitcoin Core src directory")

if(NOT EXISTS "${BITCOIN_SRC_DIR}/script/miniscript.h")
  message(FATAL_ERROR
        "Bitcoin Core source not found at ${BITCOIN_SRC_DIR}\n"
        "Please either:\n"
        "  1. Clone Bitcoin Core: git submodule add https://github.com/bitcoin/bitcoin vendor/bitcoin\n"
        "  2. Set BITCOIN_SRC_DIR to point to your Bitcoin Core src directory"
    )
endif()

# Build secp256k1 from Bitcoin Core's vendored copy
set(SECP256K1_SRC_DIR "${BITCOIN_SRC_DIR}/secp256k1")
if(NOT EXISTS "${SECP256K1_SRC_DIR}/src/secp256k1.c")
  message(FATAL_ERROR "secp256k1 source not found at ${SECP256K1_SRC_DIR}")
endif()

# Configure secp256k1 build options
set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDH ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT ON CACHE BOOL "" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)

# Add secp256k1 as a subdirectory
add_subdirectory(${SECP256K1_SRC_DIR} ${CMAKE_CURRENT_BINARY_DIR}/secp256k1 EXCLUDE_FROM_ALL)

find_package(Boost 1.73.0 REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp
    ${BITCOIN_SRC_DIR}
    ${BITCOIN_SRC_DIR}/..
    ${SECP256K1_SRC_DIR}/include
    ${Boost_INCLUDE_DIRS}
)

add_compile_definitions(
    HAVE_CONFIG_H=0
    ENABLE_WALLET=0
    SECP256K1_STATIC=1
)

string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

set(BITCOIN_CORE_SOURCES
    # Script layer
    ${BITCOIN_SRC_DIR}/script/miniscript.cpp
    ${BITCOIN_SRC_DIR}/script/script.cpp
    ${BITCOIN_SRC_DIR}/script/parsing.cpp
    ${BITCOIN_SRC_DIR}/script/descriptor.cpp
    ${BITCOIN_SRC_DIR}/script/signingprovider.cpp
    ${BITCOIN_SRC_DIR}/script/sign.cpp
    ${BITCOIN_SRC_DIR}/script/solver.cpp

    # Key handling
    ${BITCOIN_SRC_DIR}/key.cpp
    ${BITCOIN_SRC_DIR}/pubkey.cpp
    ${BITCOIN_SRC_DIR}/key_io.cpp

    # Address handling
    ${BITCOIN_SRC_DIR}/addresstype.cpp
    ${BITCOIN_SRC_DIR}/base58.cpp
    ${BITCOIN_SRC_DIR}/bech32.cpp

    # Crypto
    ${BITCOIN_SRC_DIR}/hash.cpp
    ${BITCOIN_SRC_DIR}/uint256.cpp
    ${BITCOIN_SRC_DIR}/crypto/sha256.cpp
    ${BITCOIN_SRC_DIR}/crypto/sha512.cpp
    ${BITCOIN_SRC_DIR}/crypto/ripemd160.cpp
    ${BITCOIN_SRC_DIR}/crypto/hmac_sha256.cpp
    ${BITCOIN_SRC_DIR}/crypto/hmac_sha512.cpp

    # Utilities
    ${BITCOIN_SRC_DIR}/util/strencodings.cpp
    ${BITCOIN_SRC_DIR}/util/string.cpp
    ${BITCOIN_SRC_DIR}/util/spanparsing.cpp
)

set(BITCOIN_SOURCES_FILTERED)
foreach(src ${BITCOIN_CORE_SOURCES})
  if(EXISTS ${src})
    list(APPEND BITCOIN_SOURCES_FILTERED ${src})
  endif()
endforeach()

set(WRAPPER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp/miniscript_wrapper.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp/descriptor_wrapper.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp/stubs.cpp
)

add_library(miniscript_wrapper
    ${BITCOIN_SOURCES_FILTERED}
    ${WRAPPER_SOURCES}
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  set_source_files_properties(
        ${BITCOIN_SOURCES_FILTERED}
        PROPERTIES COMPILE_FLAGS "-w"
    )

  target_compile_options(miniscript_wrapper PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -Wpedantic>
    )
endif()

target_link_libraries(miniscript_wrapper
    PRIVATE
        ${Boost_LIBRARIES}
        secp256k1
)

install(TARGETS miniscript_wrapper
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/cpp/miniscript_wrapper.h
    DESTINATION include
)

if(MINISCRIPT_WRAPPER_TESTS)
  enable_testing()

  add_executable(test_wrapper
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_wrapper.cpp
    )
  target_link_libraries(test_wrapper miniscript_wrapper)

  add_test(NAME test_wrapper COMMAND test_wrapper)
endif()
