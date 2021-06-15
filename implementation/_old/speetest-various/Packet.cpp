//
// Created by ubuntu on 04.04.21.
//

#include "Packet.h"

Packet::Packet(const unsigned char *pkt, unsigned long timestampUs) : pkt(pkt), timestamp_us(timestampUs) {}

const unsigned char *Packet::getPkt() const {
    return pkt;
}

unsigned long Packet::getTimestampUs() const {
    return timestamp_us;
}
