cmake_minimum_required(VERSION 3.9)
project(fast_pcap)

set(CMAKE_CXX_STANDARD 17)

set(Boost_DEBUG 1)
#set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREAD ON)
#set(Boost_USE_STATIC_RUNTIME OFF)

find_package(Boost REQUIRED)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIR})
    message(STATUS "Boost_LIBRARIES: ${Boost_LIBRARIES}")
    message(STATUS "Boost_LIBRARY_DIR: ${Boost_LIBRARY_DIR}")
    message(STATUS "Boost_INCLUDE_DIR: ${Boost_INCLUDE_DIR}")
endif ()

add_executable(fast_pcap src/main.cpp src/pcap_loader.cpp src/protocol_parser.cpp)

add_executable(pcap_loader_demo src/pcap_loader_demo.cpp src/pcap_loader.cpp)

add_executable(protocol_parser_demo src/protocol_parser_demo.cpp src/pcap_loader.cpp src/protocol_parser.cpp)

add_executable(fp_dump_tcp_stream src/fp_dump_tcp_stream.cpp src/pcap_loader.cpp src/protocol_parser.cpp)
target_link_libraries(fp_dump_tcp_stream ${Boost_LIBRARIES})
