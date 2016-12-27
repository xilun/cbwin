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

target_link_libraries(outbash ws2_32 iphlpapi)

if(MSVC)

    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set_target_properties(outbash PROPERTIES COMPILE_FLAGS "/Wall -Wextra") # Clang/C2
    else()
        # Additional compiler options:
        #   sdl: enable more security checks
        #   guard:cf: and then enable one more kind of security checks...
        #   GR-: disable RTTI
        #   W4: max warning level usable in practice (MSVC's Wall chokes on crt and system headers)
        #   MP: compile using multiple processes
        set_target_properties(outbash PROPERTIES COMPILE_FLAGS "/sdl /guard:cf /GR- /W4 /MP")

        # Set C++ as conforming as possible:
        set_property(TARGET outbash APPEND_STRING PROPERTY COMPILE_FLAGS " /Zc:strictStrings /Zc:rvalueCast")
        if(MSVC_VERSION GREATER 1900)
            set_property(TARGET outbash APPEND_STRING PROPERTY COMPILE_FLAGS " /permissive-")
        endif()

        # Additional compiler options for release builds:
        #   GL: enable whole program optimization (link time code gen)
        #   Gw: Optimize Global Data (allow Ref and Icf optim of const data)
        set(CMAKE_CXX_FLAGS_RELEASE        "${CMAKE_CXX_FLAGS_RELEASE}        /GL /Gw /O2 /Ob2")
        set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /GL /Gw /O1 /Ob2")
        set(CMAKE_CXX_FLAGS_MINSIZEREL     "${CMAKE_CXX_FLAGS_MINSIZEREL}     /GL /Gw /O1 /Ob2")
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

    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /guard:cf")

    set(CMAKE_EXE_LINKER_FLAGS_RELEASE        "${CMAKE_EXE_LINKER_FLAGS_RELEASE}        /INCREMENTAL:NO /LTCG:incremental /OPT:REF,ICF")
    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} /INCREMENTAL:NO /LTCG:incremental /OPT:REF,ICF")
    set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL     "${CMAKE_EXE_LINKER_FLAGS_MINSIZEREL}     /INCREMENTAL:NO /LTCG:incremental /OPT:REF,ICF")

    target_link_libraries(outbash debug -NODEFAULTLIB:libucrtd.lib debug ucrtd.lib)
    target_link_libraries(outbash optimized -NODEFAULTLIB:libucrt.lib optimized ucrt.lib)

else() # MSYS2 MinGW64 Gcc 6.2, for testing

    add_definitions(-DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00)
    set_target_properties(outbash PROPERTIES COMPILE_FLAGS "-municode -mwin32 -mthreads -std=c++14 -Wall -Wextra") # -ffunction-sections -fdata-sections
    # set(CMAKE_EXE_LINKER_FLAGS "-static") # -Wl,--gc-sections -Wl,--cref

endif()
