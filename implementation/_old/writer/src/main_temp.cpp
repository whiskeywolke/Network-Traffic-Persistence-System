#include "stdlib.h"
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PlatformSpecificUtils.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/RawPacket.h>
#include <iostream>
#include "RingBuffer/ThreadedQueue.h"
#include "reader/Reader.h"

#include <memory>

#include <boost/lockfree/queue.hpp>

/**
 * A callback function for the async capture which is called each time a packet is captured
 */
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) //TO DO add threadsafe queue as cookie, put rawpacketvoctors in it
{
    // extract the stats object form the cookie
    boost::lockfree::queue<pcpp::RawPacket*>* queue = (boost::lockfree::queue<pcpp::RawPacket*>*)cookie;
    queue->push(packet);
}

int main(int argc, char* argv[])
{
    // IPv4 address of the interface we want to sniff
    std::string interfaceIPAddr = "10.0.2.15";
    std::string inFileName = "testfiles/test5.pcap";

    Reader dev(inFileName.c_str());
    if (!dev.open())
    {
        printf("Cannot open device\n");
        exit(1);
    }
/*
    // Using filters
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
    dev->setFilter(andFilter);
*/
    // create the queue
    boost::lockfree::queue<pcpp::RawPacket*> queue(1000);



    // Async packet capture with a callback function
    printf("\nStarting async capture...\n");
    std::cout<<"queue empty: "<<queue.empty()<<std::endl;


    boost::lockfree::queue<std::shared_ptr<int>> queue2(1000);

    pcpp::RawPacket* rawPacketPointer;
    while(dev.nextRawPacket(rawPacketPointer)){
        queue.push(rawPacketPointer);
    }

    pcpp::RawPacket* derefRawPacketPointer;
    while(queue.pop(derefRawPacketPointer)){
        pcpp::Packet packet = derefRawPacketPointer;
        std::cout<<packet.toString()<<std::endl;
    }



    // print results
    std::cout<<"queue empty: "<<queue.empty()<<std::endl;

}