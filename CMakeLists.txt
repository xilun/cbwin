cmake_minimum_required(VERSION 2.8.11)

project(cbwin)

add_executable(outbash
               utf.h
               utf.cpp
               env.h
               env.cpp
               process.h
               process.cpp
               win_except.h
               win_except.cpp
               outbash.cpp)

add_definitions(/D_UNICODE /DUNICODE)

if(MSVC)
    # Wall is basically unusable as is with MSVC, because it needlessly chokes
    # on crt and system headers.
    set_target_properties(outbash PROPERTIES COMPILE_FLAGS "/W4 /D_CRT_SECURE_NO_WARNINGS")

    set(variables
      CMAKE_C_FLAGS_DEBUG
      CMAKE_C_FLAGS_MINSIZEREL
      CMAKE_C_FLAGS_RELEASE
      CMAKE_C_FLAGS_RELWITHDEBINFO
      CMAKE_CXX_FLAGS_DEBUG
      CMAKE_CXX_FLAGS_MINSIZEREL
      CMAKE_CXX_FLAGS_RELEASE
      CMAKE_CXX_FLAGS_RELWITHDEBINFO
    )
    foreach(variable ${variables})
        if(${variable} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${variable} "${${variable}}")
        endif()
    endforeach()

    target_link_libraries(outbash debug -NODEFAULTLIB:libucrtd.lib debug ucrtd.lib)
    target_link_libraries(outbash optimized -NODEFAULTLIB:libucrt.lib optimized ucrt.lib)
endif()
