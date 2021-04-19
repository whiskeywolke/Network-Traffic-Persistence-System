#include "stdlib.h"
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PlatformSpecificUtils.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/RawPacket.h>
#include <iostream>
#include "RingBuffer/ThreadedQueue.h"
#include "Reader/Reader.h"

#include <memory>

#include <boost/lockfree/queue.hpp>



int main(int argc, char* argv[])
{
    std::string inFileName = "testfiles/test6.pcap";

    Reader dev(inFileName.c_str());
    if (!dev.open())
    {
        printf("Cannot open device\n");
        exit(1);
    }


    // creating filters
    pcpp::ProtoFilter tcpProtocolFilter(pcpp::TCP);
    pcpp::ProtoFilter udpProtocolFilter(pcpp::UDP);
    pcpp::ProtoFilter icmpProtocolFilter(pcpp::ICMP);
    pcpp::ProtoFilter ipv4ProtocolFilter(pcpp::IPv4);

    pcpp::OrFilter orFilter;
    orFilter.addFilter(&tcpProtocolFilter);
    orFilter.addFilter(&udpProtocolFilter);
    orFilter.addFilter(&icmpProtocolFilter);

    pcpp::AndFilter andFilter;
    andFilter.addFilter(&ipv4ProtocolFilter);
    andFilter.addFilter(&orFilter);

    // set the filter on the device
    dev.setFilter(andFilter);
    std::string filterAsString;
    andFilter.parseToString(filterAsString);
    std::cout<<"Filter: "<< filterAsString<<std::endl;

    // create the queue
    boost::lockfree::queue<Container*> queue(1000);

    std::cout<<"queue empty: "<<queue.empty()<<std::endl;



    Container* temp;
    while(dev.next(temp)){
        queue.push(temp);
    }

    std::cout<<"insert finished: "<<dev.getParsedPackets()<<std::endl;

    Container* input = nullptr;
/*
    while(queue.pop(input)){
        pcpp::RawPacket rawPacket = pcpp::RawPacket(input->buf, input->cap_len, input->timestamp, false, input->linkLayerType);
        pcpp::Packet parsed = &rawPacket;
        std::cout<<parsed.toString()<<std::endl;

        delete[] input->buf;
        delete input;
    }
*/


    // print results
    std::cout<<"queue empty: "<<queue.empty()<<std::endl;

}