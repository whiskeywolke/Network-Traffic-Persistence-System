#include <cstdlib>
#include <pcapplusplus/PcapFileDevice.h>
#include <iostream>
#include "Converter/Converter.h"
#include "ConcurrentQueue/concurrentqueue.h"

#include "Model/CompressedBucket.h"
#include "Model/AggregateST.h"

#include <memory>
#include <thread>

#include <fstream>
#include <mutex>

std::atomic<int> readPackets{0};
std::atomic<int> convertedPackets {0};
std::atomic<int> aggregatedPackets { 0};
std::atomic<int> compressedPackets { 0};
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

void readPcapFile(const std::string& fileName, moodycamel::ConcurrentQueue<pcpp::RawPacket>* queue){
    pcpp::IFileReaderDevice* reader =  pcpp::IFileReaderDevice::getReader(fileName.c_str());

    if (reader == NULL || !reader->open())
    {
        printf("Error creating reader device\n");
        exit(1);
    }

    reader->setFilter(getPredefinedFilterAsString());

    pcpp::RawPacket temp;

    auto start = std::chrono::high_resolution_clock::now();

    while(reader->getNextPacket(temp)){
        queue->enqueue(temp);
    }
    readingFinished = true;

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "reading duration: \t\t" << duration << " nanoseconds\n";
//    std::cout << "Handling time per packet: " << duration / dev.getParsedPackets() << "; Packets per second: "<<1000000000/(duration / dev.getParsedPackets() ) <<std::endl;
        pcap_stat stats;
        reader->getStatistics(stats);
        readPackets = stats.ps_recv;
    }
}

void convert(moodycamel::ConcurrentQueue<pcpp::RawPacket>* queue1, moodycamel::ConcurrentQueue<IPTuple>* queue2){
    pcpp::RawPacket input;
    IPTuple ipTuple;

    auto start = std::chrono::high_resolution_clock::now();

    while(!readingFinished || queue1->size_approx() != 0){
        if(queue1->try_dequeue(input)) {
            if (Converter::convert(input, ipTuple)) {
                queue2->enqueue(ipTuple);
            }
        }
    }
    conversionFinished = true;
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "conversion duration: \t" << duration << " nanoseconds\n";
    }
}

void aggregateSingleThread(moodycamel::ConcurrentQueue<IPTuple>* queue1, moodycamel::ConcurrentQueue<std::vector<IPTuple>>* queue2){
    AggregateST b{};

    auto start = std::chrono::high_resolution_clock::now();
    auto time_since_flush = std::chrono::high_resolution_clock::now();
    while(!conversionFinished  || queue1->size_approx() != 0){  //TODO checking if empty only makes sense with single thread
        IPTuple t;
        if(queue1->try_dequeue(t)){
            while(!b.add(t)){};
        }
        auto current_time = std::chrono::high_resolution_clock::now();
        if(std::chrono::duration_cast<std::chrono::seconds>(current_time - time_since_flush).count() >= 2 ){
            b.flush(queue2);
            time_since_flush = current_time;
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

void compress(moodycamel::ConcurrentQueue<std::vector<IPTuple>>* queue1, moodycamel::ConcurrentQueue<CompressedBucket>* queue2) {
    auto start = std::chrono::high_resolution_clock::now();
/*    int32_t maxmaxOffset = 0;
    int32_t minminOffset = 0;
    uint64_t maxObservedPorts = 0;
    uint64_t observedPorts = 0;
    uint64_t portcountmorethan = 0;
    uint64_t maxObservedIPs = 0;
    uint64_t observerdIPs = 0;
    uint64_t ipcountmorethan = 0;
    int bucketcount = 0;
*/
    while (!aggregationFinished || queue1->size_approx() != 0) {
        std::vector<IPTuple> sorted;
        if (queue1->try_dequeue(sorted)) {
            CompressedBucket bucket;
            for (const IPTuple& ipTuple : sorted) {
                if(!bucket.add(ipTuple)){
                    //now bucket is full replace with new one
                    queue2->enqueue(bucket);
                    bucket = CompressedBucket();
//                    std::cout<<"bucket is full"<<std::endl;
//                    ++ipcountmorethan;

                }

            }
            /*
            int amount = sorted.size_approx();
            IPTuple t[amount];
            std::size_t count = sorted.try_dequeue_bulk(t, amount);
            for (size_t i = 0; i<count; ++i) {
                bucket.add(t[i]);
            }
*/
            queue2->enqueue(bucket);
//            ++bucketCount;
/*            if(bucket.getMaxOffset() > maxmaxOffset){
                maxmaxOffset = bucket.getMaxOffset();
            }
            if(bucket.getMinOffset() < minminOffset){
                minminOffset = bucket.getMinOffset();
            }
            if(bucket.portCount() > maxObservedPorts){
                maxObservedPorts = bucket.portCount();
            }
            if(bucket.portCount() > 255){
                ++portcountmorethan;
            }
            if(bucket.ipCount() > maxObservedIPs){
                maxObservedIPs = bucket.ipCount();
            }
//            if(bucket.ipCount() >= 255){
//                ++ipcountmorethan;
//            }

            ++bucketcount;
            observedPorts += bucket.portCount();
            observerdIPs += bucket.ipCount();
*/
        }
    }
    compressionFinished = true;
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "compression duration: \t" << duration << " nanoseconds\n";
/*        std::cout<<"max offset: "<<maxmaxOffset<<std::endl;
        std::cout<<"min offset: "<<minminOffset<<std::endl;
        std::cout<<"bucket count: "<<bucketcount<<std::endl;
        std::cout<<"max port count: "<<maxObservedPorts<<std::endl;
        std::cout<<"port count more than: "<<portcountmorethan<<std::endl;
        std::cout<<"port count more than%: "<<100.0*(((double)portcountmorethan)/bucketcount)<<std::endl;
        std::cout<<"average port count: "<<observedPorts/bucketcount<<std::endl;
        std::cout<<"max ip count: "<<maxObservedIPs<<std::endl;
        std::cout<<"ip count more than: "<<ipcountmorethan<<std::endl;
        std::cout<<"ip count more than%: "<<100.0*(((double)ipcountmorethan)/bucketcount)<<std::endl;
        std::cout<<"average ip count: "<<observerdIPs/bucketcount<<std::endl;
*/


    }
}

void writeToFile(moodycamel::ConcurrentQueue<CompressedBucket>* queue) {
    //TODO write group of compressedObjects (5000) to single file timestamp as name
    std::string outFileName = "/home/ubuntu/testfiles/out.bin";

    auto start = std::chrono::high_resolution_clock::now();
    {
        std::ofstream ofs(outFileName);
        boost::archive::binary_oarchive oa(ofs);
        CompressedBucket b;
        while (queue->size_approx() != 0 || !compressionFinished) {
            if (queue->try_dequeue(b)) {
                oa << b;
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

inline void join(std::vector<std::thread>& vector) {
    for(std::thread& t : vector){
        t.join();
    }
}

#define READER_THREADS 1
#define CONVERTER_THREADS 3
#define AGGREGATOR_THREADS 4
#define COMPRESSOR_THREADS 1
#define WRITER_THREADS 1
#define SEQUENTIAL false

int main(int argc, char* argv[]) {
//    std::string inFilename = "/home/ubuntu/testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"; //6.7GB      (107555567 packets) (no payload)
    std::string inFilename = "/home/ubuntu/testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap"; //1.6GB      (27013768 packets)  (no payload)
//    std::string inFilename = "/home/ubuntu/testfiles/example.pcap";
//    std::string inFilename = "/home/ubuntu/testfiles/test3.pcap";
//    std::string inFilename = "/home/ubuntu/testfiles/test4.pcap";
//    std::string inFilename = "/home/ubuntu/testfiles/test5.pcap"; //(3 packets)
//    std::string inFilename = "/home/ubuntu/testfiles/test6.pcap";  // (1031565 packets) with payload

    if((READER_THREADS+CONVERTER_THREADS+AGGREGATOR_THREADS+COMPRESSOR_THREADS+WRITER_THREADS)>std::thread::hardware_concurrency()){
        std::cout<<"REQUESTED MORE THREADS THAN SUPPORTED, PERFORMANCE MAY NOT BE OPTIMAL (supported: "<<std::thread::hardware_concurrency()
        <<", requested: "<<(READER_THREADS+CONVERTER_THREADS+AGGREGATOR_THREADS+COMPRESSOR_THREADS+WRITER_THREADS)<<")"<<std::endl;
    }

    std::vector<std::thread>readers{};
    std::vector<std::thread>converters{};
    std::vector<std::thread>aggregators{};
    std::vector<std::thread>compressors{};
    std::vector<std::thread>writers{};
    readers.reserve(READER_THREADS);
    converters.reserve(CONVERTER_THREADS);
    aggregators.reserve(AGGREGATOR_THREADS);
    compressors.reserve(COMPRESSOR_THREADS);
    writers.reserve(WRITER_THREADS);

    moodycamel::ConcurrentQueue<pcpp::RawPacket>queueRaw(10000000);
    moodycamel::ConcurrentQueue<IPTuple>queueParsed(10000000);
    moodycamel::ConcurrentQueue<std::vector<IPTuple>>queueSorted(50000);
    moodycamel::ConcurrentQueue<CompressedBucket>queueCompressed(50000);

    auto start = std::chrono::high_resolution_clock::now();

//for profiling call all functions sequential in main thread
/*    readPcapFile(std::ref(inFilename), &queueRaw);
    convert(&queueRaw, &queueParsed);
    aggregateSingleThread(&queueParsed, &queueSorted);
    compress(&queueSorted, &queueCompressed);
*/


    for(int i = 0; i < READER_THREADS; ++i){
        readers.emplace_back(readPcapFile, std::ref(inFilename), &queueRaw);
    }
    if(SEQUENTIAL){join(readers);}

    for(int i = 0; i < CONVERTER_THREADS; ++i){
        converters.emplace_back(convert, &queueRaw, &queueParsed);
    }
    if(SEQUENTIAL){join(converters);}

    for(int i = 0; i < AGGREGATOR_THREADS; ++i){
        aggregators.emplace_back(aggregateSingleThread, &queueParsed, &queueSorted);
    }
    if(SEQUENTIAL){join(aggregators);}

    for(int i = 0; i < COMPRESSOR_THREADS; ++i){
        compressors.emplace_back(compress, &queueSorted, &queueCompressed);
    }
    if(SEQUENTIAL){join(compressors);}

    for(int i = 0; i < WRITER_THREADS; ++i){
        writers.emplace_back(writeToFile, &queueCompressed);
    }
    if(SEQUENTIAL){join(writers);}

    if(!SEQUENTIAL){
        join(readers);
        join(converters);
        join(aggregators);
        join(compressors);
        join(writers);
    }


    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    std::cout << "total duration: \t\t" << duration << " nanoseconds\n";
    std::cout << "Handling time per packet: " << duration / readPackets << "; Packets per second: " << 1000000000 / (duration / readPackets ) << std::endl;
    std::cout << "Packet Count: " << readPackets << std::endl;


    // print results
    std::cout << "\nqueueRaw size: "       << queueRaw.size_approx() << std::endl;
    std::cout << "queueParsed size: "      << queueParsed.size_approx() << std::endl;
    std::cout << "queueSorted size: "      << queueSorted.size_approx() << std::endl;
    std::cout << "queueCompressed size: "  << queueCompressed.size_approx() << std::endl;

    /*
    //check that no packets have been left
    assert(queueRaw.size_approx() == 0);
    assert(queueParsed.size_approx() == 0);
    assert(queueSorted.size_approx() == 0);
    assert(queueCompressed.size_approx() == 0);
    */
    return 0;
}