//
// Created by ubuntu on 19.04.21.
//

#ifndef IMPLEMENTATION_CONVERTER_H
#define IMPLEMENTATION_CONVERTER_H

#include "../Common/IPTuple.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/IcmpLayer.h>

namespace writer {
    class Converter {
    public:
        static inline bool convert(pcpp::RawPacket &rawPacket, common::IPTuple &tuple) {
            //  pcpp::RawPacket rawPacket = pcpp::RawPacket(container->buf, container->cap_len, container->timestamp, false, container->linkLayerType);
            rawPacket.getPacketTimeStamp();
            pcpp::Packet parsedPacket = &rawPacket;
            if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
                if (parsedPacket.isPacketOfType(pcpp::TCP)) {
                    return makeIpTupleFromTCP(parsedPacket, tuple, rawPacket.getPacketTimeStamp());
                } else if (parsedPacket.isPacketOfType(pcpp::UDP)) {
                    return makeIpTupleFromUDP(parsedPacket, tuple, rawPacket.getPacketTimeStamp());
                } else if (parsedPacket.isPacketOfType(pcpp::ICMP)) {
                    return makeIpTupleFromICMP(parsedPacket, tuple, rawPacket.getPacketTimeStamp());
                }

          /*      if (parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getIPv4Header()->protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP) {
                    if(rawPacket.getLinkLayerType() == pcpp::LinkLayerType::LINKTYPE_IPV4){

                        common::IPTuple(parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                                        parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                                        ntohs(parsedPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc),
                                        ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst),
                                        UDPn,
                                        packet.getRawPacketReadOnly()->getFrameLength(),
                                        ts.tv_sec,
                                        ts.tv_nsec / 1000);
                    }
                    return makeIpTupleFromTCP(parsedPacket, tuple, rawPacket.getPacketTimeStamp());
                } else if (parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getIPv4Header()->protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP) {
                    return makeIpTupleFromUDP(parsedPacket, tuple, rawPacket.getPacketTimeStamp());
                } else if (parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getIPv4Header()->protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_ICMP) {
                    return makeIpTupleFromICMP(parsedPacket, tuple, rawPacket.getPacketTimeStamp());
                }
       */      }
            return false;
        }

        inline static bool makeIpTupleFromUDP(const pcpp::Packet &packet, common::IPTuple &tuple, timespec ts) {
            tuple = common::IPTuple(packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                                    packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                                    ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc),
                                    ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst),
                                    UDPn,
                                    packet.getRawPacketReadOnly()->getFrameLength(),
                                    ts.tv_sec,
                                    ts.tv_nsec / 1000);  //convert nanoseconds to microseconds
            return true;
        }

        inline static bool makeIpTupleFromTCP(const pcpp::Packet &packet, common::IPTuple &tuple, timespec ts) {
            tuple = common::IPTuple(packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                                    packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                                    ntohs(packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc),
                                    ntohs(packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portDst),
                                    TCPn,
                                    packet.getRawPacketReadOnly()->getFrameLength(),
                                    ts.tv_sec,
                                    ts.tv_nsec / 1000);  //convert nanoseconds to microseconds
            return true;
        }

        inline static bool makeIpTupleFromICMP(const pcpp::Packet &packet, common::IPTuple &tuple, timespec ts) {
            tuple = common::IPTuple(packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                                    packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                                    0,
                                    0,
                                    ICMPn,
                                    packet.getRawPacketReadOnly()->getFrameLength(),
                                    ts.tv_sec,
                                    ts.tv_nsec / 1000);  //convert nanoseconds to microseconds
            return true;
        }

    };
}

#endif //IMPLEMENTATION_CONVERTER_H
