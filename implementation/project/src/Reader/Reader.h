//
// Created by ubuntu on 12.04.21.
//

#ifndef IMPLEMENTATION_READER_H
#define IMPLEMENTATION_READER_H

#include <boost/lockfree/queue.hpp>

#include <pcap.h>

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFilter.h>
#include "../Model/IPTuple.h"
#include <arpa/inet.h>
#include "../Model/RawContainer.h"


class Reader{ ///inspired by https://github.com/seladb/PcapPlusPlus/blob/master/Pcap%2B%2B/src/PcapFileDevice.cpp
private:
    const char * fileName;
    pcap_t *descr = NULL;
    pcpp::LinkLayerType linkLayerType;

    bool isOpen = false;
    int parsedPacketCount;
    int UDPCount;
    int TCPCount;
    int ICMPCount;

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
        this->parsedPacketCount = 0;
        this->UDPCount = 0;
        this->TCPCount = 0;
        this->ICMPCount = 0;
        return true;
    }

    bool setFilter(pcpp::GeneralFilter& filter){
        std::string filterAsString{};
        filter.parseToString(filterAsString);
        return setFilter(filterAsString);
    }

    bool setFilter(std::string filterAsString){
        if(!this->isOpen){
            std::cout<<"open device first!"<<std::endl;
            return false;
        }
        struct bpf_program prog;
        if (pcap_compile(this->descr, &prog, filterAsString.c_str(), 1, 0) < 0)
        {
            printf("Error compiling filter. Error message is: %s", pcap_geterr(descr));
            pcap_freecode(&prog); //frees memory allocated by pcap_compile
            return false;
        }
        if (pcap_setfilter(this->descr, &prog) < 0)
        {
            printf("Error setting a compiled filter. Error message is: %s", pcap_geterr(this->descr));
            pcap_freecode(&prog);
            return false;
        }
        pcap_freecode(&prog);
        return true;
    }

/*
    bool nextRawPacket(pcpp::RawPacket rawPacket){
        if(descr == NULL){
            /// Need to open reader first
            return false;
        }
        pcap_pkthdr pkthdr;
        const uint8_t* packetData = pcap_next(descr, &pkthdr);
        if (packetData == NULL){
            ///could not readFromPcap packet -> most likely EOF
            return false;
        }

        uint8_t* newPacketData = new uint8_t[pkthdr.caplen];
        memcpy(newPacketData, packetData, pkthdr.caplen);

        rawPacket.clear();

        if(!rawPacket.setRawData(newPacketData,pkthdr.caplen,pkthdr.ts, linkLayerType, pkthdr.len)){
            ///could not create rawpacket from data
            std::cout<<"could not set rawpacket"<<std::endl;
            return false;
        }

        ++parsedPacketCount;
        return true;
    }
*/
    bool next(RawContainer* &rawPacket){
        if(descr == NULL){
            /// Need to open reader first
            return false;
        }
        pcap_pkthdr pkthdr;
        const uint8_t* packetData = pcap_next(descr, &pkthdr);
        if (packetData == NULL){
            ///could not readFromPcap packet -> most likely EOF
            return false;
        }

        uint8_t* newPacketData = new uint8_t[pkthdr.caplen];
        memcpy(newPacketData, packetData, pkthdr.caplen);

        rawPacket = new RawContainer;


        rawPacket->buf = newPacketData;
        rawPacket->cap_len = pkthdr.caplen;
        rawPacket->timestamp = pkthdr.ts;
        rawPacket->linkLayerType = linkLayerType;
        rawPacket->hdrlen = pkthdr.len;

/*
        std::cout<<std::endl;
        std::cout<<pkthdr.caplen<<std::endl;
        std::cout<<pkthdr.len<<std::endl;
*/
        ++parsedPacketCount;
        return true;
    }


/*
/// retrieves next IPTuple -> looks for the next IPTuple that is either TCP, UDP or ICMP
    bool nextIpTuple(IPTuple &tuple){
        pcpp::RawPacket temp;

        do{
            if(!nextRawPacket(temp)){
                ///could not get next rawpacket
                return false;
            }
            pcpp::Packet parsedPacket = &temp;
            if(parsedPacket.isPacketOfType(pcpp::IPv4)) {
                if (parsedPacket.isPacketOfType(pcpp::TCP)) {
                    ++TCPCount;
                    return makeIpTupleFromTCP(parsedPacket, tuple);
                } else if (parsedPacket.isPacketOfType(pcpp::UDP)) {
                    ++UDPCount;
                    return makeIpTupleFromUDP(parsedPacket, tuple);
                } else if (parsedPacket.isPacketOfType(pcpp::ICMP)) {
                    ++ICMPCount;
                    return makeIpTupleFromICMP(parsedPacket, tuple);
                }
            }
        } while (true);
        return false;
    }
*/
    int getParsedPackets() const {
        return parsedPacketCount;
    }

    int getConvertedPackets() const {
        return TCPCount+UDPCount+ICMPCount;
    }

    int getSkippedPackets() const {
        return getParsedPackets()-getConvertedPackets();
    }

    int getUdpCount() const {
        return UDPCount;
    }

    int getTcpCount() const {
        return TCPCount;
    }

    int getIcmpCount() const {
        return ICMPCount;
    }
};

#endif //IMPLEMENTATION_READER_H
