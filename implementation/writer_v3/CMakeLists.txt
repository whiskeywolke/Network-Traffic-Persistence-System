cmake_minimum_required(VERSION 3.17)
project(implementation)



set(CMAKE_CXX_STANDARD 14)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")
include(cmake/FindPCAP.cmake)
include(GNUInstallDirs)
find_package(PCAP REQUIRED)
#find_package(PCAPPLUSPLUS REQUIRED)

link_directories(/usr/local/lib/pcappluplus)
#find_library(PCAPPLUSPLUS_LIBRARY
#        NAMES libpacket++ pcapplusplus
#        HINTS /usr/local/lib)

#find_path(PCAPPLUSPLUS_INCLUD_DIR
#        NAMES pcapplusplus Packet.h
#        HINTS /usr/local/include/pcapplusplus
#        )

#add_library(pcapplusplus SHARED IMPORTED)
#find_package(pcapplusplus COMPONENTS system filesystem REQUIRED)

#include_directories(${pcapplusplus_INCLUDE_DIRS})

add_executable(pcappp_test src/reader_main.cpp src/writer_main.cpp src/Model/IPTuple.h src/Converter/Converter.h src/Model/SortST.h src/Model/CompressedBucket.h src/ src/Model/MetaBucket.h)

#target_link_libraries(BoostTest ${pcapplusplus_LIBRARIES})

target_link_libraries(pcappp_test ${PCAP_LIBRARY})
target_link_libraries(pcappp_test /usr/local/lib/libCommon++.a)
target_link_libraries(pcappp_test /usr/local/lib/libPacket++.a)
target_link_libraries(pcappp_test /usr/local/lib/libPcap++.a)
#target_link_libraries(pcappp_test ${PCAPPLUSPLUS})
#set_target_properties(pcapplusplus PROPERTIES IMPORTED_LOCATION "/usr/local/include/pcapplusplus")