#include "stdlib.h"
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PlatformSpecificUtils.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/RawPacket.h>
#include <iostream>
#include "RingBuffer/ThreadedQueue.h"
#include "Reader/Reader.h"
#include "Converter/Converter.h"

#include <memory>
#include <thread>

#include <boost/lockfree/queue.hpp>

bool readingFinished = false;

std::string getPredefinedFilterAsString(){
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

    std::string res{};
    andFilter.parseToString(res);
    return res;
}


void readPcapFile(const std::string& fileName, boost::lockfree::queue<RawContainer*>* queue){
//void readPcapFile(const std::string& fileName, ThreadedQueue<RawContainer*>* queue){
    Reader dev(fileName.c_str());
    if (!dev.open())
    {
        printf("Cannot open device\n");
        exit(1);
    }
    dev.setFilter(getPredefinedFilterAsString());
    RawContainer* temp;

    auto start = std::chrono::high_resolution_clock::now();

    while(dev.next(temp)){
        queue->push(temp);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
    std::cout << "reading duration: " << duration << " nanoseconds\n";
    std::cout << "Handling time per packet: " << duration / dev.getParsedPackets() << std::endl;
    std::cout << "Packet Count: " << dev.getParsedPackets() << std::endl;
    readingFinished = true;
}

void convert(boost::lockfree::queue<RawContainer*>* queue1, boost::lockfree::queue<IPTuple>* queue2){
//void convert(ThreadedQueue<RawContainer*>* queue1, ThreadedQueue<IPTuple>* queue2){
    RawContainer* input = nullptr;

    auto start = std::chrono::high_resolution_clock::now();


    while(!readingFinished ){
        IPTuple ipTuple;
        if(queue1->pop(input)) {
            if (Converter::convert(input, ipTuple)) {
                //std::cout << ipTuple.toString() << std::endl;
                queue2->push(ipTuple);
            }

            // free memory allocated while reading
            delete[] input->buf;
            delete input;
        }
        input = nullptr;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
    std::cout << "conversion duration: " << duration << " nanoseconds\n";

}




int main(int argc, char* argv[])
{
    std::string inFilename = "./testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"; //6.7GB      (107555567 packets) (no payload)
//    std::string inFilename = "./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap"; //1.6GB      (27013768 packets)  (no payload)
//    std::string inFilename = "./testfiles/example.pcap";
//    std::string inFilename = "./testfiles/test3.pcap";
//    std::string inFilename = "./testfiles/test4.pcap";
//    std::string inFilename = "./testfiles/test5.pcap"; //(3 packets)
//    std::string inFilename = "./testfiles/test6.pcap";  // (1031565 packets) with payload



    boost::lockfree::queue<RawContainer*> queue1{100000};
    boost::lockfree::queue<IPTuple> queue2{100000};

    ThreadedQueue<RawContainer*> tQueue1{};
    ThreadedQueue<IPTuple> tQueue2{};

    auto start = std::chrono::high_resolution_clock::now();

    std::thread th1(readPcapFile, std::ref(inFilename), &queue1);


    std::thread th2(convert, &queue1, &queue2); //more than one converter thread reduces performance (synchronization overhead)
   // std::thread th3(convert, &queue1, &queue2);
   // std::thread th4(convert, &queue1, &queue2);

    th1.join();
    th2.join();
   // th3.join();
   // th4.join();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
    std::cout << "total duration: " << duration << " nanoseconds\n";



    // print results
    std::cout<<"queue empty: "<<queue1.empty()<<std::endl;

}