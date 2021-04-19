#include "stdlib.h"
//#include <pcapplusplus/PcapLiveDeviceList.h>
//#include <pcapplusplus/PlatformSpecificUtils.h>
#include <pcapplusplus/PcapFileDevice.h>
//#include <pcapplusplus/RawPacket.h>
#include <iostream>
#include "RingBuffer/ThreadedQueue.h"
#include "Reader/Reader.h"
#include "Converter/Converter.h"
#include "Model/Bucket.h"

#include <memory>
#include <thread>

#include <boost/lockfree/queue.hpp>

bool readingFinished = false;
int parsedPackets = 0;
std::atomic<int> processedPackets { 0};

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
    parsedPackets = dev.getParsedPackets();
    readingFinished = true;
}

void convert(boost::lockfree::queue<RawContainer*>* queue1, boost::lockfree::queue<IPTuple>* queue2){
    RawContainer* input = nullptr;

    auto start = std::chrono::high_resolution_clock::now();


    while(!readingFinished || processedPackets<parsedPackets){
        IPTuple ipTuple;
        if(queue1->pop(input)) {
            if (Converter::convert(input, ipTuple)) {
                //std::cout << ipTuple.toString() << std::endl;
                //std::cout<<"timestamp "<<input->timestamp.tv_sec<<" "<< input->timestamp.tv_usec <<std::endl;

                queue2->push(ipTuple);
            }

            // free memory allocated while reading
            delete[] input->buf;
            delete input;
            ++processedPackets;
        }
        input = nullptr;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
    std::cout << "conversion duration: " << duration << " nanoseconds\n";

}

void aggregate(boost::lockfree::queue<IPTuple>* queue1, boost::lockfree::queue<SortedPackets*>* queue2){
    Bucket b{};


    auto start = std::chrono::high_resolution_clock::now();
    auto time_since_flush = std::chrono::high_resolution_clock::now();
    while(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count() <= 10 ){
        IPTuple t;
        if(queue1->pop(t)){
            b.add(t);
        }
        auto current_time = std::chrono::high_resolution_clock::now();
        if(std::chrono::duration_cast<std::chrono::seconds>(current_time - time_since_flush).count() >= 1 ){
            b.flush(queue2);
            time_since_flush = current_time;
            std::cout<<"flushing"<<std::endl;
        }
    }
    b.flush(queue2);

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



    boost::lockfree::queue<RawContainer*> queueRaw{10000};
    boost::lockfree::queue<IPTuple> queueParsed{10000};

    auto start = std::chrono::high_resolution_clock::now();

    std::thread th1(readPcapFile, std::ref(inFilename), &queueRaw);

    //th1.join();

    std::thread th2(convert, &queueRaw, &queueParsed); //more than one converter thread reduces performance (synchronization overhead), probably system dependant
    //std::thread th3(convert, &queueRaw, &queueParsed);

    th1.join();
    th2.join();
    //th3.join();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
    std::cout << "total duration: " << duration << " nanoseconds\n";

    //TODO aggregate packets by IP in buckets

    std::cout<<"start bucket"<<std::endl;
    boost::lockfree::queue<SortedPackets*> queueBuckets{1000};

    aggregate(&queueParsed, &queueBuckets);



    while (!queueBuckets.empty()){
        SortedPackets* sp;
        if(queueBuckets.pop(sp)){
            std::cout<<"elements in Bucket: "<<sp->length<<std::endl;
          //  for(size_t i = 0; i < sp->length; ++i){
          //      std::cout<<sp->start[i].toString()<<std::endl;
          //  }
            delete[] sp->start;
            delete sp;
        }
    }


    std::cout<<"end bucket"<<std::endl;



    // print results
    std::cout << "queueRaw empty: " << queueRaw.empty() << std::endl;
    std::cout << "queueParsed empty: " << queueParsed.empty() << std::endl;
    std::cout << "queueBuckets empty: " << queueBuckets.empty() << std::endl;

}