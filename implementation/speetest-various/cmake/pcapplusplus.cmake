
find_library(PCAP_LIB pcap)
find_file(PCAP_INC pcap)

if(NOT PCAP_LIB OR NOT PCAP_INC)
    set(WITH_PCAP FALSE)
    message(WARNING "Detecting libpcap: not found - disable support")
else()
    message(STATUS "Detecting libpcap: PCAP_LIB:${PCAP_LIB}, PCAP_INC:${PCAP_INC} - done")
    add_definitions(-DWITH_PCAP=1)
endif(NOT PCAP_LIB OR NOT PCAP_INC)