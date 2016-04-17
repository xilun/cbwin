cmake_minimum_required(VERSION 2.8.11)

project(cbwin)

add_executable(outbash
               outbash.cpp)

if(MSVC)
    # Wall is basically unusable as is with MSVC, because it needlessly chokes
    # on crt and system headers.
    set_target_properties(outbash PROPERTIES COMPILE_FLAGS "/W4 /D_CRT_SECURE_NO_WARNINGS")
endif()
