find_path(PCAPPLUSPLUS_ROOT_DIR
        NAMES include/pcapplusplus
        )

find_path(PCAPPLUSPLUS_INCLUDE_DIR
        NAMES pcap.h
        HINTS ${PCAP_ROOT_DIR}/include
        )

find_library(PCAP_LIBRARY
        NAMES pcap
        HINTS ${PCAP_ROOT_DIR}/lib
        )