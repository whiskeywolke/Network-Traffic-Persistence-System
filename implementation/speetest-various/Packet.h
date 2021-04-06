//
// Created by ubuntu on 04.04.21.
//

#ifndef UNTITLED_PACKET_H
#define UNTITLED_PACKET_H


class Packet {
private:
    const unsigned char* pkt;
    unsigned long timestamp_us;
public:
    Packet(const unsigned char *pkt, unsigned long timestampUs);

    const unsigned char *getPkt() const;

    unsigned long getTimestampUs() const;
};


#endif //UNTITLED_PACKET_H
