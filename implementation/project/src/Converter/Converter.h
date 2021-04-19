//
// Created by ubuntu on 19.04.21.
//

#ifndef IMPLEMENTATION_CONVERTER_H
#define IMPLEMENTATION_CONVERTER_H

#include "../Model/RawContainer.h"
#include "../Model/IPTuple.h"

class Converter {
public:
    static bool convert(const RawContainer* container, IPTuple& tuple){
        pcpp::RawPacket rawPacket = pcpp::RawPacket(container->buf, container->cap_len, container->timestamp, false, container->linkLayerType);
        pcpp::Packet parsedPacket = &rawPacket;
        if(parsedPacket.isPacketOfType(pcpp::IPv4)) {
            if (parsedPacket.isPacketOfType(pcpp::TCP)) {
                return makeIpTupleFromTCP(parsedPacket, tuple);
            } else if (parsedPacket.isPacketOfType(pcpp::UDP)) {
                return makeIpTupleFromUDP(parsedPacket, tuple);
            } else if (parsedPacket.isPacketOfType(pcpp::ICMP)) {
                return makeIpTupleFromICMP(parsedPacket, tuple);
            }
        }
        return false;
    }

    inline static bool makeIpTupleFromUDP(const pcpp::Packet& packet, IPTuple& tuple) {
        tuple = IPTuple(packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                        packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                        ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc),
                        ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst),
                        17);
        return true;
    }
    inline static bool makeIpTupleFromTCP(const pcpp::Packet& packet, IPTuple& tuple) {
        tuple = IPTuple(packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                        packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                        ntohs(packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc),
                        ntohs(packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portDst),
                        6);
        return true;
    }
    inline static bool makeIpTupleFromICMP(const pcpp::Packet& packet, IPTuple& tuple) {
        tuple = IPTuple(packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                        packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                        0,
                        0,
                        1);
        return true;
    }

};


#endif //IMPLEMENTATION_CONVERTER_H
