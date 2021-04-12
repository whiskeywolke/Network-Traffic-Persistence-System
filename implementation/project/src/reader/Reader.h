//
// Created by ubuntu on 12.04.21.
//

#ifndef IMPLEMENTATION_READER_H
#define IMPLEMENTATION_READER_H

#include <boost/lockfree/queue.hpp>
#include <pcapplusplus/PcapFileDevice.h>

#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/IcmpLayer.h>

#include <pcap.h>



#define BATCHSIZE  100


class Reader{ ///inspired by https://github.com/seladb/PcapPlusPlus/blob/master/Pcap%2B%2B/src/PcapFileDevice.cpp
private:
    const char * fileName;
    pcap_t *descr = NULL;
    pcpp::LinkLayerType linkLayerType;

    bool isOpen = false;
    int parsedPackets;
    int convertedPackets;


public:
    Reader(const char* filename){
        this->fileName = filename;
    }

    bool open(){
        if(descr != NULL){
            ///already opened
            return true;
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        this->descr = pcap_open_offline(fileName, errbuf);
        if(descr == NULL){
            ///could not open file
            isOpen = false;
            return false;
        }

        int linkLayer = pcap_datalink(descr);
        if (!pcpp::RawPacket::isLinkTypeValid(linkLayer))
        {
            printf("Invalid link layer (%d) for reader device filename '%s'", linkLayer, fileName);
            pcap_close(descr);
            descr = NULL;
            isOpen = false;
            return false;
        }
        this->linkLayerType = static_cast<pcpp::LinkLayerType>(linkLayer);
        this->isOpen = true;
        this->parsedPackets = 0;
        this->convertedPackets = 0;

        return true;
    }

    bool nextRawPacket(pcpp::RawPacket &rawPacket){
        if(descr == NULL){
            /// Need to open reader first
            return false;
        }
        pcap_pkthdr pkthdr;
        const uint8_t* packetData = pcap_next(descr, &pkthdr);
        if (packetData == NULL){
            ///could not read packet -> most likely EOF
            return false;
        }


        uint8_t* newPacketData = new uint8_t[pkthdr.caplen];
        memcpy(newPacketData, packetData, pkthdr.caplen);

        rawPacket.clear();
        if(!rawPacket.setRawData(newPacketData,pkthdr.caplen,pkthdr.ts, linkLayerType, pkthdr.len)){
            ///could not creat rawpacket from data
            return false;
        }
        ++parsedPackets;
        return true;
    }

    inline bool makeIpTupleFromUDP(const pcpp::Packet& packet, IPTuple& tuple) {
        std::cout<<"okay1"<<std::endl;

        auto a = packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
        std::cout<<"okay2"<<std::endl;

        auto b = packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();
        std::cout<<"okay3"<<std::endl;
 /*       auto c = ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc);
        auto d = ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst);
        std::cout<<"okay"<<std::endl;
*/
  //      tuple = IPTuple(a,b,0,0, 17);
    /*    tuple = IPTuple(packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                        packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                        ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc),
                        ntohs(packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst),
                        17);
      */  return true;
    }
    inline bool makeIpTupleFromTCP(const pcpp::Packet& packet, IPTuple& tuple) {
        tuple = IPTuple(packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                        packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                        ntohs(packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc),
                        ntohs(packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portDst),
                        6);
        return true;
    }
    inline bool makeIpTupleFromICMP(const pcpp::Packet& packet, IPTuple& tuple) {
        tuple = IPTuple(packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                        packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                        0,
                        0,
                        1);
        return true;
    }

/// retrieves next IPTuple -> looks for the next IPTuple that is either TCP, UDP or ICMP
    bool nextIpTuple(IPTuple &tuple){
        pcpp::RawPacket temp;

        do{
            if(!nextRawPacket(temp)){
                ///could not get next rawpacket
                return false;
            }
            pcpp::Packet parsedPacket = &temp;
            if(parsedPacket.isPacketOfType(pcpp::UDP)){   //TODO error if header was truncated access to fields not guaranteed
                ++convertedPackets;
                return makeIpTupleFromUDP(parsedPacket, tuple);
            }
            else if(parsedPacket.isPacketOfType(pcpp::TCP)){
                ++convertedPackets;
                return makeIpTupleFromTCP(parsedPacket, tuple);
            }
            else if(parsedPacket.isPacketOfType(pcpp::ICMP)){
                ++convertedPackets;
                return makeIpTupleFromICMP(parsedPacket, tuple);
            }
        } while (true);
    }

    int getParsedPackets() const {
        return parsedPackets;
    }

    int getConvertedPackets() const {
        return convertedPackets;
    }

};

/*
class Reader2 {
    //TODO adapt to also read ethernet device

    pcpp::PcapFileReaderDevice reader;

public:
    Reader(const char* filename){
        this->reader = pcpp::PcapFileReaderDevice::getReader(filename);
        if (!reader.open()){
            throw "error opening the pcap file";
        }
    }

    virtual ~Reader() {
        this->reader.close();
    }

    int getNextPackets(boost::lockfree::queue<pcpp::RawPacketVector*> queue){
        pcpp::RawPacketVector packetVec;
        int temp = this->reader.getNextPackets(packetVec, BATCHSIZE);
        queue.push(&packetVec);
        return temp;
    }

};
*/

#endif //PCAPPP_TEST_READER_H
