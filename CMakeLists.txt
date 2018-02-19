
cmake_minimum_required(VERSION 3.0)


SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DPAM_EMAIL_DEBUG=1")

add_subdirectory (src)
