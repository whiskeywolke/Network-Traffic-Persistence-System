cmake_minimum_required(VERSION 3.17)
project(untitled)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fopenmp")

include(cmake/findpcap.cmake) #https://github.com/bro/cmake/blob/master/FindPCAP.cmake
add_executable(untitled main.cpp gpv.cpp gpv.h pcap_reader.cpp pcap_reader.h util.cpp util.h om.h Packet.cpp Packet.h model/pcapentry.cpp model/pcapentry.h)

target_link_libraries(untitled ${PCAP_LIBRARY})


LINK_DIRECTORIES(${CMAKE_BINARY_DIR}/res)
TARGET_LINK_LIBRARIES(untitled
        /usr/local/lib/libCommon++.a
        /usr/local/lib/libPacket++.a
        /usr/local/lib/libPcap++.a
)

#target_include_directories(untitled /usr/local/include/pcapplusplus/)
#target_include_directories("${PROJECT_SOURCE_DIR}"/include "/usr/local/include/")
#target_link_libraries(untitled /usr/local/include/pcapplusplus/PcapFileDevice.h)
#target_link_libraries(untitled ~/PcapPlusPlus-20.08/Common++)


