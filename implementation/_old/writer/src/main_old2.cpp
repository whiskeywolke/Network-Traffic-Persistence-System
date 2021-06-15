#include "stdlib.h"
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PlatformSpecificUtils.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <iostream>
#include "RingBuffer/ThreadedQueue.h"

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
    std::string inFileName = "10.0.2.15";



    // find the interface by IP address
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr.c_str());

    pcpp::IFileReaderDevice* dev2= pcpp::IFileReaderDevice::getReader(inFileName.c_str());
    if (dev == NULL)
    {
        printf("Cannot find interface with IPv4 address of '%s'\n", interfaceIPAddr.c_str());
        exit(1);
    }

    // open the device before start capturing/sending packets
    if (!dev->open())
    {
        printf("Cannot open device\n");
        exit(1);
    }

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

    // create the queue
    boost::lockfree::queue<pcpp::RawPacket*> queue(1000);


    // Async packet capture with a callback function
    printf("\nStarting async capture...\n");
    std::cout<<"queue empty: "<<queue.empty()<<std::endl;

    // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
    dev->startCapture(onPacketArrives, &queue);
    // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
    PCAP_SLEEP(10);

    // stop capturing packets
    dev->stopCapture();

    // print results
    std::cout<<"queue empty: "<<queue.empty()<<std::endl;
    while (!queue.empty()){
        pcpp::RawPacket* p;
        queue.pop(p);
        pcpp::Packet parsed = p;
        std::cout<<parsed.toString()<<std::endl;
    }


    // close the device before application ends
    dev->close();
}