#include <cstdlib>
#include <pcapplusplus/PcapFileDevice.h>
#include <iostream>
#include "Converter/Converter.h"
#include "ConcurrentQueue/concurrentqueue.h"

#include <boost/archive/binary_oarchive.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>

#include "Model/CompressedBucket.h"
#include "Model/MetaBucket.h"
#include "Model/SortST.h"

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
std::atomic<bool> sortingFinished {false};
std::atomic<bool> compressionFinished {false};
std::atomic<bool> aggregationFinished {false};
std::atomic<bool> writingFinished {false};

std::mutex print_mutex;
std::mutex status_mutex;

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

void readPcapFile(const std::string& fileName, std::vector<bool>* status, int threadID, moodycamel::ConcurrentQueue<pcpp::RawPacket>* outQueue){
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
        outQueue->enqueue(temp);
        ++readPackets;
    }
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if(std::find(status->begin(), status->end(), false) == status->end()){  //false cannot be found -> all other threads are finished
            readingFinished = true;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "reading duration: \t\t" << duration << " nanoseconds\n";
//    std::cout << "Handling time per packet: " << duration / dev.getParsedPackets() << "; Packets per second: "<<1000000000/(duration / dev.getParsedPackets() ) <<std::endl;
        pcap_stat stats;
        reader->getStatistics(stats);
        //readPackets = stats.ps_recv;
    }
}

void convert(std::vector<bool>* status, int threadID, moodycamel::ConcurrentQueue<pcpp::RawPacket>* inQueue, moodycamel::ConcurrentQueue<IPTuple>* outQueue){
    pcpp::RawPacket input;
    IPTuple ipTuple;

//    int counter = 0;
    auto start = std::chrono::high_resolution_clock::now();

    while(!readingFinished || inQueue->size_approx() != 0){
        if(inQueue->try_dequeue(input)) {
            if (Converter::convert(input, ipTuple)) {
                outQueue->enqueue(ipTuple);
//                ++counter;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if(std::find(status->begin(), status->end(), false) == status->end()){  //false cannot be found -> all other threads are finished
            conversionFinished = true;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "conversion duration: \t" << duration << " nanoseconds\n";
//        std::cout << "conversion count: \t" << counter << " packets\n";
    }
}

void sortSingleThread(std::vector<bool>* status, int threadID, moodycamel::ConcurrentQueue<IPTuple>* inQueue, moodycamel::ConcurrentQueue<std::vector<IPTuple>>* outQueue){
    //TODO find out why packets sorting is more efficient if run sequential
    SortST b{};
//    int enqueueCounter = 0;
//    int dequeueCounter = 0;

    auto start = std::chrono::high_resolution_clock::now();
    auto time_since_flush = std::chrono::high_resolution_clock::now();
    while(!conversionFinished || inQueue->size_approx() != 0){
        IPTuple t;
        if(inQueue->try_dequeue(t)){
//            ++dequeueCounter;
            while(!b.add(t)){};
        }
        auto current_time = std::chrono::high_resolution_clock::now();
        if(std::chrono::duration_cast<std::chrono::seconds>(current_time - time_since_flush).count() >= 2 ){
//            enqueueCounter+=b.size();
            b.flush(outQueue);
            time_since_flush = current_time;
        }
    }
//    enqueueCounter+=b.size();
    b.flush(outQueue);
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if(std::find(status->begin(), status->end(), false) == status->end()){  //false cannot be found -> all other threads are finished
            sortingFinished = true;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "sorting duration: \t\t" << duration << " nanoseconds\n";
//        std::cout << "sorting dequeue: \t\t" << dequeueCounter << "\n";
//        std::cout << "sorting enqueue: \t\t" << enqueueCounter << "\n";
    }
}

void compress(std::vector<bool>* status, int threadID, moodycamel::ConcurrentQueue<std::vector<IPTuple>>* inQueue, moodycamel::ConcurrentQueue<CompressedBucket>* outQueue) {
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

    int enqueueCounter = 0;
    int dequeueCounter = 0;
    size_t packetCounter = 0;
*/
    while (!sortingFinished || inQueue->size_approx() != 0) {
        std::vector<IPTuple> sorted;
        if (inQueue->try_dequeue(sorted)) {
//            ++dequeueCounter;
//            packetCounter += sorted.size();
            CompressedBucket bucket;
            for (const IPTuple& ipTuple : sorted) {
                if(!bucket.add(ipTuple)){
                    //now bucket is full replace with new one
                    outQueue->enqueue(bucket);
//                    ++enqueueCounter;
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
            if(bucket.getHasFirst()) { //check if bucket is not empty
                outQueue->enqueue(bucket);
//                ++enqueueCounter;
            }
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
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if(std::find(status->begin(), status->end(), false) == status->end()){  //false cannot be found -> all other threads are finished
            compressionFinished = true;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "compression duration: \t" << duration << " nanoseconds\n";
/*        std::cout << "compression dequeue: \t" << dequeueCounter << "\n";
        std::cout << "compression enqueue: \t" << enqueueCounter << "\n";
        std::cout << "compression packetcount: \t" << packetCounter << "\n";
        std::cout<<"max offset: "<<maxmaxOffset<<std::endl;
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

void aggregate(std::vector<bool>* status, int threadID, moodycamel::ConcurrentQueue<CompressedBucket>* inQueue, moodycamel::ConcurrentQueue<MetaBucket>* outQueue){
    auto start = std::chrono::high_resolution_clock::now();

    uint32_t tuples = 0;
//    int outCounter = 0;

    MetaBucket meta{};
    auto metaLifetime = std::chrono::high_resolution_clock::now();
    while(!compressionFinished || inQueue->size_approx() != 0){
        CompressedBucket b;
        if(inQueue->try_dequeue(b)){
//            ++counter;
            tuples += b.size();
            if(!meta.add(b)){ //metabucket is full
                if(outQueue->enqueue(meta)) {
 //                   std::cout<<"full"<<std::endl;
                    meta = MetaBucket();
//                    ++outCounter;
                    metaLifetime = std::chrono::high_resolution_clock::now();
                }
            }
            auto current_time = std::chrono::high_resolution_clock::now();
            if(std::chrono::duration_cast<std::chrono::seconds>(current_time - metaLifetime).count() >= 10 ){ //metabucket lives already to long
                if(outQueue->enqueue(meta)) {
//                    ++outCounter;
 //                   std::cout<<"to long"<<std::endl;
                    meta = MetaBucket();
                    metaLifetime = current_time;
                }
            }
        }
    }
    if(meta.size() != 0) {
        while (!outQueue->enqueue(meta)); //enqueue last metabucket
//        ++outCounter;
 //       std::cout<<"left over"<<std::endl;
    }
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if(std::find(status->begin(), status->end(), false) == status->end()){  //false cannot be found -> all other threads are finished
            aggregationFinished = true;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "aggregation duration: \t" << duration << " nanoseconds\n";
        std::cout << "aggregation tuples: \t" << tuples << " packets\n";
//        std::cout << "aggregation dequeue: \t" << counter<<std::endl;
//        std::cout << "aggregation out: \t" << outCounter << std::endl;
    }
}

void writeToFile(std::vector<bool>* status, int threadID, moodycamel::ConcurrentQueue<MetaBucket>* inQueue, std::string outFilePath) {
    auto start = std::chrono::high_resolution_clock::now();
   {
        MetaBucket b;
        while (!aggregationFinished || inQueue->size_approx() != 0) {
            if (inQueue->try_dequeue(b)) {
                std::string outFileName = outFilePath + b.getFileName() + ".bin";
                std::ofstream ofs(outFileName);
                boost::archive::binary_oarchive oa(ofs);
                oa << b;
            }
        }
    }
/*
    std::ofstream ofs(outFileName, std::ios::binary);
    {
        boost::iostreams::filtering_ostreambuf fos;

        // push the ofstream and the compressor
        fos.push(boost::iostreams::gzip_compressor (boost::iostreams::gzip::best_speed));
        fos.push(ofs);

        // start the archive on the filtering buffer:
        boost::archive::binary_oarchive bo(fos);
        MetaBucket b;
        while (inQueue->size_approx() != 0 || !compressionFinished) {
            if (inQueue->try_dequeue(b)) {
                bo << b;
            }
        }
    }

*/
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
#define CONVERTER_THREADS 1
#define SORTER_THREADS 4
#define COMPRESSOR_THREADS 1
#define AGGREGATOR_THREADS 1
#define WRITER_THREADS 2
#define SEQUENTIAL false

//TODO merge compression & aggregation step

int main(int argc, char* argv[]) {

    std::vector<std::string>inputFiles{
            "/home/ubuntu/testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap", //6.7GB      (107555567 packets) (no payload)
            "/home/ubuntu/testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap", //1.6GB      (27013768 packets)  (no payload)
            "/home/ubuntu/testfiles/test6.pcap",  // (1031565 packets) with payload
            "/home/ubuntu/testfiles/example.pcap",
            "/home/ubuntu/testfiles/test3.pcap",
            "/home/ubuntu/testfiles/test4.pcap",
            "/home/ubuntu/testfiles/test5.pcap", //(3 packets)
    };
//    std::string inFilename = "/home/ubuntu/testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"; //6.7GB      (107555567 packets) (no payload)

    if((READER_THREADS + CONVERTER_THREADS + SORTER_THREADS + COMPRESSOR_THREADS + AGGREGATOR_THREADS + WRITER_THREADS) > std::thread::hardware_concurrency()){
        std::cout << "REQUESTED MORE THREADS THAN SUPPORTED, PERFORMANCE MAY NOT BE OPTIMAL (supported: " << std::thread::hardware_concurrency()
                  << ", requested: " << (READER_THREADS + CONVERTER_THREADS + SORTER_THREADS + COMPRESSOR_THREADS + AGGREGATOR_THREADS + WRITER_THREADS) << ")" << std::endl;
    }



    std::string outFilePath = "./"; //default directory
    std::string inFilename;
    bool file = false;
    for(int i = 1; i < argc; ++i){
        if(strcmp(argv[i], "-o") == 0){ // output directory specified
            outFilePath = argv[++i];
            if(outFilePath.at(outFilePath.size()-1) != '/'){
                outFilePath.append("/");
            }
        }
        if(strcmp(argv[i], "-fI") == 0){
            inFilename = inputFiles.at(atoi(argv[++i]));
            file = true;
        }
        if(strcmp(argv[i], "-f") == 0){
            inFilename = argv[++i];
            file = true;
        }
    }
    std::cout<<"Writing to directory: " + outFilePath<<std::endl;
    if(file) {
        std::cout <<"Reading from file: "<<inFilename<<std::endl;
    }else{
        std::cout<<"no file specified"<<std::endl;
        return 0;
    }

    std::vector<std::thread>readers{};
    std::vector<std::thread>converters{};
    std::vector<std::thread>sorters{};
    std::vector<std::thread>compressors{};
    std::vector<std::thread>aggregators{};
    std::vector<std::thread>writers{};
    readers.reserve(READER_THREADS);
    converters.reserve(CONVERTER_THREADS);
    sorters.reserve(SORTER_THREADS);
    compressors.reserve(COMPRESSOR_THREADS);
    aggregators.reserve(AGGREGATOR_THREADS);
    writers.reserve(WRITER_THREADS);

    std::vector<bool>readerStatus(READER_THREADS, false);
    std::vector<bool>converterStatus(CONVERTER_THREADS, false);
    std::vector<bool>sorterStatus(SORTER_THREADS, false);
    std::vector<bool>compressorStatus(COMPRESSOR_THREADS, false);
    std::vector<bool>aggregatorStatus(AGGREGATOR_THREADS, false);
    std::vector<bool>writerStatus(WRITER_THREADS, false);


    moodycamel::ConcurrentQueue<pcpp::RawPacket>queueRaw(10000000);
    moodycamel::ConcurrentQueue<IPTuple>queueParsed(10000000);
    moodycamel::ConcurrentQueue<std::vector<IPTuple>>queueSorted(50000);
    moodycamel::ConcurrentQueue<CompressedBucket>queueCompressed(50000);
    moodycamel::ConcurrentQueue<MetaBucket>queueFiles(50000);


    auto start = std::chrono::high_resolution_clock::now();

//for profiling call all functions sequential in main thread
/*    readPcapFile(std::ref(inFilename), &queueRaw);
    convert(&queueRaw, &queueParsed);
    sortSingleThread(&queueParsed, &queueSorted);
    compress(&queueSorted, &queueCompressed);
*/


    for(int i = 0; i < READER_THREADS; ++i){
        readers.emplace_back(readPcapFile, std::ref(inFilename), &readerStatus, i, &queueRaw);
    }
    if(SEQUENTIAL){join(readers);}

    for(int i = 0; i < CONVERTER_THREADS; ++i){
        converters.emplace_back(convert, &converterStatus, i, &queueRaw, &queueParsed);
    }
    if(SEQUENTIAL){join(converters);}

    for(int i = 0; i < SORTER_THREADS; ++i){
        sorters.emplace_back(sortSingleThread, &sorterStatus, i, &queueParsed, &queueSorted);
    }
    if(SEQUENTIAL){join(sorters);}

    for(int i = 0; i < COMPRESSOR_THREADS; ++i){
        compressors.emplace_back(compress, &compressorStatus, i, &queueSorted, &queueCompressed);
    }
    if(SEQUENTIAL){join(compressors);}

    for(int i = 0; i < AGGREGATOR_THREADS; ++i){
        aggregators.emplace_back(aggregate, &aggregatorStatus, i, &queueCompressed, &queueFiles);
    }
    if(SEQUENTIAL){join(aggregators);}

    for(int i = 0; i < WRITER_THREADS; ++i){
        writers.emplace_back(writeToFile, &writerStatus, i, &queueFiles, outFilePath);
    }
    if(SEQUENTIAL){join(writers);}

    if(!SEQUENTIAL){
        join(readers);
        join(converters);
        join(sorters);
        join(compressors);
        join(aggregators);
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
    std::cout << "queueFiles size: "       << queueFiles.size_approx() << std::endl;


    //check that no packets have been left
    assert(queueRaw.size_approx() == 0);
    assert(queueParsed.size_approx() == 0);
    assert(queueSorted.size_approx() == 0);
    assert(queueCompressed.size_approx() == 0);
    assert(queueFiles.size_approx() == 0);

    return 0;
}