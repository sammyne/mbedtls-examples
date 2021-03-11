cmake_minimum_required(VERSION 3.16)

project(mbedtls-examples)

option(ENABLE_TESTING "enable testing" Off)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)
include(cmake/vendor.cmake)

#message("hello ${mbedtlsBinDir}-${mbedtlsDir}")

include_directories(${mbedtlsDir}/include)
link_directories(${mbedtlsBinDir}/library)

add_subdirectory(secp256r1)
