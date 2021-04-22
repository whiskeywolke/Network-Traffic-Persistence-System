#include "stdlib.h"
//#include <pcapplusplus/PcapLiveDeviceList.h>
//#include <pcapplusplus/PlatformSpecificUtils.h>
#include <pcapplusplus/PcapFileDevice.h>
//#include <pcapplusplus/RawPacket.h>
#include <iostream>
#include "RingBuffer/ThreadedQueue.h"
#include "Reader/Reader.h"
#include "Converter/Converter.h"
#include "Model/Aggregate2.h"

//#include "Model/Aggregate.h"
#include "Model/CompressedBucket.h"

#include <memory>
#include <thread>

#include <boost/lockfree/queue.hpp>
#include <fstream>

std::atomic<int> parsedPackets{0};
std::atomic<int> processedPackets { 0};
std::atomic<bool> readingFinished {false};
std::atomic<bool> conversionFinished {false};
std::atomic<bool> aggregationFinished {false};
std::atomic<bool> compressionFinished {false};
std::atomic<bool> writingFinished {false};

std::mutex print_mutex;

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
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "reading duration: \t\t" << duration << " nanoseconds\n";
//    std::cout << "Handling time per packet: " << duration / dev.getParsedPackets() << "; Packets per second: "<<1000000000/(duration / dev.getParsedPackets() ) <<std::endl;
        parsedPackets = dev.getParsedPackets();
    }
    readingFinished = true;
}

void convert(boost::lockfree::queue<RawContainer*>* queue1, boost::lockfree::queue<IPTuple>* queue2){
    RawContainer* input = nullptr;

    auto start = std::chrono::high_resolution_clock::now();


    while(!readingFinished || processedPackets<parsedPackets || !queue1->empty()){
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
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "conversion duration: \t" << duration << " nanoseconds\n";
    }
    conversionFinished = true;
}

void aggregate(boost::lockfree::queue<IPTuple>* queue1, boost::lockfree::queue<SortedPackets*>* queue2){
    Aggregate2& b = Aggregate2::getInstance();
    b.setID();

    auto start = std::chrono::high_resolution_clock::now();
    auto time_since_flush = std::chrono::high_resolution_clock::now();
    //while(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count() <= 10){
    while(!conversionFinished || !queue1->empty()){  //TODO checking if empty only makes sense with single thread
        IPTuple t;
        if(queue1->pop(t)){
            while(!b.add(t)){};
        }
        auto current_time = std::chrono::high_resolution_clock::now();
        if(std::chrono::duration_cast<std::chrono::seconds>(current_time - time_since_flush).count() >= 2 ){
            b.flush(queue2);
            time_since_flush = current_time;
            //std::cout<<"flushing"<<std::endl;
        }
    }
    b.flush(queue2);
    aggregationFinished = true;
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "aggregation duration: \t" << duration << " nanoseconds\n";
    }
}

void compress(boost::lockfree::queue<SortedPackets*>* queue1, boost::lockfree::queue<CompressedBucket*>* queue2) {
    int bucketCount = 0;
    int sum = 0;
    size_t largestBucket = 0;
    auto start = std::chrono::high_resolution_clock::now();

    while (!queue1->empty() || !aggregationFinished) {
        SortedPackets *sp;
        if (queue1->pop(sp)) {
            sum += sp->length;
            if (sp->length > largestBucket) {
                largestBucket = sp->length;
            }
            CompressedBucket *bucket = new CompressedBucket{};
            std::vector<IPTuple> temp{};
            for (size_t i = 0; i < sp->length; ++i) {
                bucket->add(sp->start[i]);
                temp.push_back(sp->start[i]);
            }
            queue2->push(bucket);
            //cleanup

            delete[] sp->start;
            delete sp;
            ++bucketCount;
        }
    }
    compressionFinished = true;
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "compression duration: \t" << duration << " nanoseconds\n";
//    std::cout << "average packets per bucket: " << sum / bucketCount << std::endl;
//    std::cout << "largest bucket: " << largestBucket << std::endl;

    }
}

void writeToFile(boost::lockfree::queue<CompressedBucket*>* queue) {
    //TODO write group of compressedObjects (5000) to single file timestamp as name
    std::string outFileName = "./testfiles/out.bin";

    auto start = std::chrono::high_resolution_clock::now();
    {
        std::ofstream ofs(outFileName);
        boost::archive::binary_oarchive oa(ofs);
        CompressedBucket *b;
        while (!queue->empty() || !compressionFinished) {
            if (queue->pop(b)) {
                oa << *b;
                delete b;
            }
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "writing duration: \t\t" << duration << " nanoseconds\n";
    }
}

int main(int argc, char* argv[]) {
//    std::string inFilename = "./testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"; //6.7GB      (107555567 packets) (no payload)
    std::string inFilename = "./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap"; //1.6GB      (27013768 packets)  (no payload)
//    std::string inFilename = "./testfiles/example.pcap";
//    std::string inFilename = "./testfiles/test3.pcap";
//    std::string inFilename = "./testfiles/test4.pcap";
//    std::string inFilename = "./testfiles/test5.pcap"; //(3 packets)
//    std::string inFilename = "./testfiles/test6.pcap";  // (1031565 packets) with payload


    boost::lockfree::queue<RawContainer *> queueRaw{10000000};
    boost::lockfree::queue<IPTuple> queueParsed{10000000};
    boost::lockfree::queue<SortedPackets *> queueSorted{50000};
    boost::lockfree::queue<CompressedBucket *> queueCompressed{50000};


    auto start = std::chrono::high_resolution_clock::now();

    std::thread th1(readPcapFile, std::ref(inFilename), &queueRaw);
//    th1.join();

    std::thread th2(convert, &queueRaw, &queueParsed); //more than one converter thread reduces performance (synchronization overhead), probably system dependant
    std::thread th21(convert, &queueRaw, &queueParsed); //more than one converter thread reduces performance (synchronization overhead), probably system dependant
//    th2.join();
//    th21.join();

    std::thread th3(aggregate, &queueParsed, &queueSorted); //aggregation seems to be the bottleneck
    std::thread th31(aggregate, &queueParsed, &queueSorted); //aggregation seems to be the bottleneck
    std::thread th32(aggregate, &queueParsed, &queueSorted); //aggregation seems to be the bottleneck
    std::thread th33(aggregate, &queueParsed, &queueSorted); //aggregation seems to be the bottleneck
//    th3.join();
//    th31.join();
//    th32.join();
//    th33.join();

    std::thread th4(compress, &queueSorted, &queueCompressed);
//    th4.join();

    std::thread th5(writeToFile, &queueCompressed);
//    th5.join();


    th1.join();
    th2.join();
    th21.join();
    th3.join();
    th31.join();
    th32.join();
    th33.join();
    th4.join();
    th5.join();

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    std::cout << "total duration: \t\t" << duration << " nanoseconds\n";
    std::cout << "Handling time per packet: " << duration / parsedPackets << "; Packets per second: "<<1000000000/(duration / parsedPackets ) <<std::endl;
    std::cout << "Packet Count: " << parsedPackets << std::endl;


    // print results
    std::cout << "\nqueueRaw empty: "       << queueRaw.empty() << std::endl;
    std::cout << "queueParsed empty: "      << queueParsed.empty() << std::endl;
    std::cout << "queueSorted empty: "      << queueSorted.empty() << std::endl;
    std::cout << "queueCompressed empty: "  << queueCompressed.empty() << std::endl;

}