cmake_minimum_required(VERSION 3.20)

project(MdnsListener VERSION 0.2.0 LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static CRT everywhere, so the exe needs no VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

configure_file(src/gui/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/generated/version.h @ONLY)

# Decoder, conversation table, hex dump and socket listener: no UI.
add_library(mdnscore STATIC
    src/core/Capture.cpp
    src/core/Capture.h
    src/core/Conversations.cpp
    src/core/Conversations.h
    src/core/Dns.cpp
    src/core/Dns.h
    src/core/HexDump.cpp
    src/core/HexDump.h
    src/core/Listener.cpp
    src/core/Listener.h
    src/core/Sequence.cpp
    src/core/Sequence.h
)
target_include_directories(mdnscore PUBLIC src/core)
target_compile_definitions(mdnscore PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00)
target_link_libraries(mdnscore PUBLIC ws2_32 iphlpapi)

add_executable(MdnsListener WIN32
    src/gui/Main.cpp
    src/gui/SequenceView.cpp
    src/gui/SequenceView.h
    src/gui/MdnsListener.rc
    src/gui/MdnsListener.manifest
)
target_include_directories(MdnsListener PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(MdnsListener PRIVATE mdnscore comctl32 comdlg32 shell32)

enable_testing()
add_executable(test_mdns tests/test_mdns.cpp)
target_link_libraries(test_mdns PRIVATE mdnscore)
add_test(NAME test_mdns COMMAND test_mdns)
add_executable(test_capture tests/test_capture.cpp)
target_link_libraries(test_capture PRIVATE mdnscore)
add_test(NAME test_capture COMMAND test_capture)

if(MSVC)
    foreach(target mdnscore MdnsListener test_mdns test_capture)
        target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4 /WX /permissive- /utf-8>)
    endforeach()
endif()
