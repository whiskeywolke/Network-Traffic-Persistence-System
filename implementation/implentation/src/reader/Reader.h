//
// Created by ubuntu on 12.04.21.
//

#ifndef IMPLEMENTATION_READER_H
#define IMPLEMENTATION_READER_H

#include <boost/lockfree/queue.hpp>
#include <pcapplusplus/PcapFileDevice.h>

#define BATCHSIZE  100


class Reader {
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


#endif //PCAPPP_TEST_READER_H
