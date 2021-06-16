//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_CONVERTER_H
#define IMPLEMENTATION_CONVERTER_H

#define MINICMPHEADERLENGTH 20
#define MINICMPPKTLENGTH 21

#define MINUDPHEADERLENGTH 24
#define MINUDPPKTLENGTH 26

#define MINTCPHEADERLENGTH 24
#define MINTCPPKTLENGTH 28

namespace reader{
    inline void makeIcmpPacket(const common::IPTuple &t, unsigned char *icmp) {
        icmp[0] = 0x45; //declare as IPv4 Packet
        icmp[9] = 0x01; //declare next layer as icmp

        uint32_t srcAddrInt = t.getV4Src();
        unsigned char srcAddrBytes[4];
        memcpy(srcAddrBytes, &srcAddrInt, sizeof(srcAddrBytes));

        uint32_t dstAddrInt = t.getV4Dst();
        unsigned char dstAddrBytes[4];
        memcpy(dstAddrBytes, &dstAddrInt, sizeof(dstAddrBytes));

        icmp[12] = srcAddrBytes[0];
        icmp[13] = srcAddrBytes[1];
        icmp[14] = srcAddrBytes[2];
        icmp[15] = srcAddrBytes[3];

        icmp[16] = dstAddrBytes[0];
        icmp[17] = dstAddrBytes[1];
        icmp[18] = dstAddrBytes[2];
        icmp[19] = dstAddrBytes[3];
    }

    inline void makeUdpPacket(const common::IPTuple &t, unsigned char *udp) {
        udp[0] = 0x45; //declare as IPv4 Packet
        udp[9] = 0x11; //declare next layer as udp

        uint32_t srcAddrInt = t.getV4Src();
        unsigned char srcAddrBytes[4];
        memcpy(srcAddrBytes, &srcAddrInt, sizeof(srcAddrBytes));

        uint32_t dstAddrInt = t.getV4Dst();
        unsigned char dstAddrBytes[4];
        memcpy(dstAddrBytes, &dstAddrInt, sizeof(dstAddrBytes));

        udp[12] = srcAddrBytes[0];
        udp[13] = srcAddrBytes[1];
        udp[14] = srcAddrBytes[2];
        udp[15] = srcAddrBytes[3];

        udp[16] = dstAddrBytes[0];
        udp[17] = dstAddrBytes[1];
        udp[18] = dstAddrBytes[2];
        udp[19] = dstAddrBytes[3];

        uint16_t srcPortInt = t.getPortSrc();
        unsigned char srcPortBytes[2];
        srcPortBytes[0] = (srcPortInt >> 8) & 0xFF;
        srcPortBytes[1] = (srcPortInt) & 0xFF;

        uint16_t dstPortInt = t.getPortDst();
        unsigned char dstPortBytes[2];
        dstPortBytes[0] = (dstPortInt >> 8) & 0xFF;
        dstPortBytes[1] = (dstPortInt) & 0xFF;

        udp[20] = srcPortBytes[0];
        udp[21] = srcPortBytes[1];

        udp[22] = dstPortBytes[0];
        udp[23] = dstPortBytes[1];
    }

    inline void makeTcpPacket(const common::IPTuple &t, unsigned char *tcp) {
        tcp[0] = 0x45; //declare as IPv4 Packet
        tcp[9] = 0x06; //declare next layer as TCPn

        uint32_t srcAddrInt = t.getV4Src();
        unsigned char srcAddrBytes[4];
        memcpy(srcAddrBytes, &srcAddrInt, sizeof(srcAddrBytes));

        uint32_t dstAddrInt = t.getV4Dst();
        unsigned char dstAddrBytes[4];
        memcpy(dstAddrBytes, &dstAddrInt, sizeof(dstAddrBytes));

        tcp[12] = srcAddrBytes[0];
        tcp[13] = srcAddrBytes[1];
        tcp[14] = srcAddrBytes[2];
        tcp[15] = srcAddrBytes[3];

        tcp[16] = dstAddrBytes[0];
        tcp[17] = dstAddrBytes[1];
        tcp[18] = dstAddrBytes[2];
        tcp[19] = dstAddrBytes[3];

        uint16_t srcPortInt = t.getPortSrc();
        unsigned char srcPortBytes[2];
        srcPortBytes[0] = (srcPortInt >> 8) & 0xFF;
        srcPortBytes[1] = (srcPortInt) & 0xFF;

        uint16_t dstPortInt = t.getPortDst();
        unsigned char dstPortBytes[2];
        dstPortBytes[0] = (dstPortInt >> 8) & 0xFF;
        dstPortBytes[1] = (dstPortInt) & 0xFF;

        tcp[20] = srcPortBytes[0];
        tcp[21] = srcPortBytes[1];

        tcp[22] = dstPortBytes[0];
        tcp[23] = dstPortBytes[1];
    }

}

#endif //IMPLEMENTATION_CONVERTER_H
