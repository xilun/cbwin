cmake_minimum_required(VERSION 3.6)

project(cbwin)

add_executable(outbash
               utf.h
               utf.cpp
               env.h
               env.cpp
               redirects.h
               redirects.cpp
               win_except.h
               win_except.cpp
               ntsuspend.h
               ntsuspend.cpp
               security.h
               security.cpp
               job.h
               job.cpp
               handle.h
               tcp_help.h
               tcp_help.cpp
               resources.h
               outbash.cpp
               outbash.rc)

add_definitions(/D_UNICODE /DUNICODE /DNOMINMAX)

if(MSVC)

    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set_target_properties(outbash PROPERTIES COMPILE_FLAGS "/Wall -Wextra")
    else()
        # Wall is basically unusable as is with MSVC, because it needlessly chokes
        # on crt and system headers.
        set_target_properties(outbash PROPERTIES COMPILE_FLAGS "/Gy /GL /GR- /W4 /D_CRT_SECURE_NO_WARNINGS /MP")
        if(MSVC_VERSION GREATER 1900)
            set_property(TARGET outbash APPEND_STRING PROPERTY COMPILE_FLAGS " /permissive-")
        endif()
    endif()

    set(variables
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
        if(${variable} MATCHES "/DNDEBUG")
            string(REGEX REPLACE "/DNDEBUG" "" ${variable} "${${variable}}")
        endif()
    endforeach()

    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG:incremental /OPT:REF,ICF")
    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} /LTCG:incremental /OPT:REF,ICF")

    target_link_libraries(outbash debug -NODEFAULTLIB:libucrtd.lib debug ucrtd.lib)
    target_link_libraries(outbash optimized -NODEFAULTLIB:libucrt.lib optimized ucrt.lib)
endif()
