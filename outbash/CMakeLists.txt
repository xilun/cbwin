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
               ntsuspend.h
               ntsuspend.cpp
               job.h
               job.cpp
               handle.h
               outbash.cpp
               outbash.rc)

add_definitions(/D_UNICODE /DUNICODE /DNOMINMAX)

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
        # in general, statically link (target_link_libraries below are an exception for the ucrt):
        if(${variable} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${variable} "${${variable}}")
        endif()
        # remove NDEBUG to keep assertions:
        if(${variable} MATCHES "/D NDEBUG")
            string(REGEX REPLACE "/D NDEBUG" "" ${variable} "${${variable}}")
        endif()
    endforeach()

    target_link_libraries(outbash debug -NODEFAULTLIB:libucrtd.lib debug ucrtd.lib)
    target_link_libraries(outbash optimized -NODEFAULTLIB:libucrt.lib optimized ucrt.lib)
endif()
