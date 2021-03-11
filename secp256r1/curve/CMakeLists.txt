cmake_minimum_required(VERSION 3.16)

add_executable(mul mul.cxx)
target_link_libraries(mul mbedtls)
