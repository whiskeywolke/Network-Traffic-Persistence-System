#include <cstdlib>
#include <iostream>
#include <memory>
#include <thread>
#include <fstream>
#include <mutex>
#include <dirent.h>
#include <sys/stat.h>

#include <boost/archive/binary_oarchive.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <pcapplusplus/PcapFileDevice.h>

#include "Model/CompressedBucket.h"
#include "Model/MetaBucket.h"
#include "Model/SortST.h"
#include "Converter/Converter.h"
#include "ConcurrentQueue/concurrentqueue.h"


std::atomic<unsigned int> readPackets{0};

std::atomic<bool> readingFinished{false};
std::atomic<bool> conversionFinished{false};
std::atomic<bool> sortingFinished{false};
std::atomic<bool> compressionFinished{false};
std::atomic<bool> aggregationFinished{false};

std::atomic<long> readingDuration{0};
std::atomic<long> conversionDuration{0};
std::atomic<long> sortingDuration{0};
std::atomic<long> compressionDuration{0};
std::atomic<long> aggregationDuration{0};
std::atomic<long> writingDuration{0};

std::mutex status_mutex;

std::string getPredefinedFilterAsString() {
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

uint64_t getTotalFilesSize(const char *path) { //works only in linux
    struct dirent *entry;
    DIR *dir = opendir(path);

    if (dir == nullptr) {
        std::cout << "dir is null" << std::endl;
        return {};
    }
    uint64_t filesizeBytes = 0;
    while ((entry = readdir(dir)) != nullptr) {
        std::string filename = entry->d_name;
        if (filename.length() == 37 && filename.substr(33, 36) == ".bin" && filename.at(16) == '-') {
            struct stat st;
            if(stat((path+filename).c_str(),&st)==0)
                filesizeBytes += st.st_size;
            else{
                closedir(dir);
                exit(1);
            }
        }
    }
    closedir(dir);
    return filesizeBytes;
}

void readPcapFile(const std::string &fileName, std::vector<bool> *status, int threadID,
                  moodycamel::ConcurrentQueue<pcpp::RawPacket> *outQueue) {
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(fileName.c_str());

    if (reader == nullptr || !reader->open()) {
        printf("Error creating reader device\n");
        exit(1);
    }
    reader->setFilter(getPredefinedFilterAsString());
    pcpp::RawPacket temp;
    auto start = std::chrono::high_resolution_clock::now();
    while (reader->getNextPacket(temp)) {
        outQueue->enqueue(temp);
    }
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if (std::find(status->begin(), status->end(), false) ==
            status->end()) {  //false cannot be found -> all other threads are finished
            readingFinished = true;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    readingDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    pcap_stat stats{};
    reader->getStatistics(stats);
    readPackets += stats.ps_recv;
}

void convert(std::vector<bool> *status, int threadID, moodycamel::ConcurrentQueue<pcpp::RawPacket> *inQueue,
             moodycamel::ConcurrentQueue<IPTuple> *outQueue) {
    pcpp::RawPacket input;
    IPTuple ipTuple;

    auto start = std::chrono::high_resolution_clock::now();
    while (!readingFinished || inQueue->size_approx() != 0) {
        if (inQueue->try_dequeue(input)) {
            if (Converter::convert(input, ipTuple)) {
                outQueue->enqueue(ipTuple);
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if (std::find(status->begin(), status->end(), false) ==
            status->end()) {  //false cannot be found -> all other threads are finished
            conversionFinished = true;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    conversionDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
}

void sortSingleThread(std::vector<bool> *status, int threadID, moodycamel::ConcurrentQueue<IPTuple> *inQueue,
                      moodycamel::ConcurrentQueue<std::vector<IPTuple>> *outQueue) {
    SortST b{};
    auto start = std::chrono::high_resolution_clock::now();
    auto time_since_flush = std::chrono::high_resolution_clock::now();
    while (!conversionFinished || inQueue->size_approx() != 0) {
        IPTuple t;
        if (inQueue->try_dequeue(t)) {
            while (!b.add(t)) {}
        }
        auto current_time = std::chrono::high_resolution_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(current_time - time_since_flush).count() >= 2) {
            b.flush(outQueue);
            time_since_flush = current_time;
        }
    }
    b.flush(outQueue);
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if (std::find(status->begin(), status->end(), false) ==
            status->end()) {  //false cannot be found -> all other threads are finished
            sortingFinished = true;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    sortingDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
}

void compress(std::vector<bool> *status, int threadID, moodycamel::ConcurrentQueue<std::vector<IPTuple>> *inQueue,
              moodycamel::ConcurrentQueue<CompressedBucket> *outQueue) {
    auto start = std::chrono::high_resolution_clock::now();

    while (!sortingFinished || inQueue->size_approx() != 0) {
        std::vector<IPTuple> sorted;
        if (inQueue->try_dequeue(sorted)) {
            CompressedBucket bucket;
            for (const IPTuple &ipTuple : sorted) {
                if (!bucket.add(ipTuple)) {//now bucket is full replace with new one & add packet to new bucket
                    outQueue->enqueue(bucket);
                    bucket = CompressedBucket();
                    bucket.add(ipTuple);
                }
            }
            if (bucket.getHasFirst()) { //check if bucket is not empty
                outQueue->enqueue(bucket);
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if (std::find(status->begin(), status->end(), false) ==
            status->end()) {  //false cannot be found -> all other threads are finished
            compressionFinished = true;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    compressionDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
/*
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "compression dequeue: \t" << dequeueCounter << "\n";
        std::cout << "compression enqueue: \t" << enqueueCounter << "\n";
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

    }
*/
}

void aggregate(std::vector<bool> *status, int threadID, moodycamel::ConcurrentQueue<CompressedBucket> *inQueue,
               moodycamel::ConcurrentQueue<MetaBucket> *outQueue) {
    auto start = std::chrono::high_resolution_clock::now();

    MetaBucket meta{};
    auto metaLifetime = std::chrono::high_resolution_clock::now();
    while (!compressionFinished || inQueue->size_approx() != 0) {
        CompressedBucket b;
        if (inQueue->try_dequeue(b)) {
            if (!meta.add(b)) { //metabucket is full
                if (outQueue->enqueue(meta)) {
                    meta = MetaBucket();
                    metaLifetime = std::chrono::high_resolution_clock::now();
                }
            }
            auto current_time = std::chrono::high_resolution_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(current_time - metaLifetime).count() >=
                10) { //metabucket lives already to long
                if (outQueue->enqueue(meta)) {
                    meta = MetaBucket();
                    metaLifetime = current_time;
                }
            }
        }
    }
    if (meta.size() != 0) {
        while (!outQueue->enqueue(meta)); //enqueue last metabucket
    }
    {
        std::lock_guard<std::mutex> lock(status_mutex);
        status->at(threadID) = true;
        if (std::find(status->begin(), status->end(), false) ==
            status->end()) {  //false cannot be found -> all other threads are finished
            aggregationFinished = true;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    aggregationDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
}

void writeToFile(std::vector<bool> *status, int threadID, moodycamel::ConcurrentQueue<MetaBucket> *inQueue,
                 const std::string &outFilePath) {
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
    auto end = std::chrono::high_resolution_clock::now();
    writingDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
}

inline void join(std::vector<std::thread> &vector) {
    for (std::thread &t : vector) {
        t.join();
    }
}

#define READER_THREADS 1
#define CONVERTER_THREADS 2
#define SORTER_THREADS 4
#define COMPRESSOR_THREADS 1
#define AGGREGATOR_THREADS 1
#define WRITER_THREADS 2

//TODO merge compression & aggregation step
int main(int argc, char *argv[]) {

    std::vector<std::string> inputFiles{
            "/home/ubuntu/testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap", //6.7GB      (107555567 packets) (no payload)
            "/home/ubuntu/testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap", //1.6GB      (27013768 packets)  (no payload)
            "/home/ubuntu/testfiles/test6.pcap",  // (1031565 packets) with payload
            "/home/ubuntu/testfiles/example.pcap",
            "/home/ubuntu/testfiles/test3.pcap",
            "/home/ubuntu/testfiles/test4.pcap",
            "/home/ubuntu/testfiles/test5.pcap", //(3 packets)
    };

    if ((READER_THREADS + CONVERTER_THREADS + SORTER_THREADS + COMPRESSOR_THREADS + AGGREGATOR_THREADS +
         WRITER_THREADS) > std::thread::hardware_concurrency()) {
        std::cout << "REQUESTED MORE THREADS THAN SUPPORTED, PERFORMANCE MAY NOT BE OPTIMAL (supported: "
                  << std::thread::hardware_concurrency()
                  << ", requested: "
                  << (READER_THREADS + CONVERTER_THREADS + SORTER_THREADS + COMPRESSOR_THREADS + AGGREGATOR_THREADS +
                      WRITER_THREADS) << ")" << std::endl;
    }

    std::string outFilePath = "./"; //default directory
    std::string inFilename;
    bool file = false;
    bool sequentialExecution = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-o") == 0) { // output directory specified
            outFilePath = argv[++i];
            if (outFilePath.at(outFilePath.size() - 1) != '/') {
                outFilePath.append("/");
            }
        }
        if (strcmp(argv[i], "-fI") == 0) { //using hardcoded predefined file
            inFilename = inputFiles.at(atoi(argv[++i]));
            file = true;
        }
        if (strcmp(argv[i], "-f") == 0) {
            inFilename = argv[++i];
            file = true;
        }
        if (strcmp(argv[i], "-s") == 0) {
            sequentialExecution = true;
        }
    }
    if (sequentialExecution) {
        std::cout << "WARNING: Running in sequential mode\n";
    }
    if (file) {
        std::cout << "Reading from file: " << inFilename << "\n";
    } else {
        std::cout << "no file specified, exiting now\n";
        return 0;
    }
    std::cout << "Writing to directory: " + outFilePath << "\n";

    std::vector<std::thread> readers{};
    std::vector<std::thread> converters{};
    std::vector<std::thread> sorters{};
    std::vector<std::thread> compressors{};
    std::vector<std::thread> aggregators{};
    std::vector<std::thread> writers{};
    readers.reserve(READER_THREADS);
    converters.reserve(CONVERTER_THREADS);
    sorters.reserve(SORTER_THREADS);
    compressors.reserve(COMPRESSOR_THREADS);
    aggregators.reserve(AGGREGATOR_THREADS);
    writers.reserve(WRITER_THREADS);

    std::vector<bool> readerStatus(READER_THREADS, false);
    std::vector<bool> converterStatus(CONVERTER_THREADS, false);
    std::vector<bool> sorterStatus(SORTER_THREADS, false);
    std::vector<bool> compressorStatus(COMPRESSOR_THREADS, false);
    std::vector<bool> aggregatorStatus(AGGREGATOR_THREADS, false);
    std::vector<bool> writerStatus(WRITER_THREADS, false);

    moodycamel::ConcurrentQueue<pcpp::RawPacket> queueRaw(10000000);
    moodycamel::ConcurrentQueue<IPTuple> queueParsed(10000000);
    moodycamel::ConcurrentQueue<std::vector<IPTuple>> queueSorted(50000);
    moodycamel::ConcurrentQueue<CompressedBucket> queueCompressed(50000);
    moodycamel::ConcurrentQueue<MetaBucket> queueFiles(50000);

    auto start = std::chrono::high_resolution_clock::now();

//for profiling call all functions sequential in main thread
/*
    readPcapFile(std::ref(inFilename), &queueRaw);
    convert(&queueRaw, &queueParsed);
    sortSingleThread(&queueParsed, &queueSorted);
    compress(&queueSorted, &queueCompressed);
*/

    for (int i = 0; i < READER_THREADS; ++i) {
        readers.emplace_back(readPcapFile, std::ref(inFilename), &readerStatus, i, &queueRaw);
    }
    if (sequentialExecution) { join(readers); }

    for (int i = 0; i < CONVERTER_THREADS; ++i) {
        converters.emplace_back(convert, &converterStatus, i, &queueRaw, &queueParsed);
    }
    if (sequentialExecution) { join(converters); }

    for (int i = 0; i < SORTER_THREADS; ++i) {
        sorters.emplace_back(sortSingleThread, &sorterStatus, i, &queueParsed, &queueSorted);
    }
    if (sequentialExecution) { join(sorters); }

    for (int i = 0; i < COMPRESSOR_THREADS; ++i) {
        compressors.emplace_back(compress, &compressorStatus, i, &queueSorted, &queueCompressed);
    }
    if (sequentialExecution) { join(compressors); }

    for (int i = 0; i < AGGREGATOR_THREADS; ++i) {
        aggregators.emplace_back(aggregate, &aggregatorStatus, i, &queueCompressed, &queueFiles);
    }
    if (sequentialExecution) { join(aggregators); }

    for (int i = 0; i < WRITER_THREADS; ++i) {
        writers.emplace_back(writeToFile, &writerStatus, i, &queueFiles, outFilePath);
    }
    if (sequentialExecution) { join(writers); }

    if (!sequentialExecution) {
        join(readers);
        join(converters);
        join(sorters);
        join(compressors);
        join(aggregators);
        join(writers);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    // print results
    std::cout << "\navg reading duration: \t\t" << readingDuration / READER_THREADS << " nanoseconds\n";
    std::cout << "avg conversion duration: \t" << conversionDuration / CONVERTER_THREADS << " nanoseconds\n";
    std::cout << "avg sorting duration: \t\t" << sortingDuration / SORTER_THREADS << " nanoseconds\n";
    std::cout << "avg compression duration: \t" << compressionDuration / COMPRESSOR_THREADS << " nanoseconds\n";
    std::cout << "avg aggregation duration: \t" << aggregationDuration / AGGREGATOR_THREADS << " nanoseconds\n";
    std::cout << "avg writing duration: \t\t" << writingDuration / WRITER_THREADS << " nanoseconds\n";

    std::cout << "\ntotal absolute duration: \t\t" << duration << " nanoseconds\n";
    std::cout << "Handling time per packet: " << duration / readPackets << "; Packets per second: "
              << 1000000000 / (duration / readPackets) << "\n";
    std::cout << "Packet Count: " << readPackets << "\n";
    std::cout << "Total File size: " << getTotalFilesSize(outFilePath.c_str()) <<" Bytes \n";
    std::cout << "Avg Bytes per Packet: " << (getTotalFilesSize(outFilePath.c_str())+0.0)/readPackets <<" Bytes \n";

    std::cout << "\nqueueRaw size: " << queueRaw.size_approx() << "\n";
    std::cout << "queueParsed size: " << queueParsed.size_approx() << "\n";
    std::cout << "queueSorted size: " << queueSorted.size_approx() << "\n";
    std::cout << "queueCompressed size: " << queueCompressed.size_approx() << "\n";
    std::cout << "queueFiles size: " << queueFiles.size_approx() << "\n";

    //check that no packets have been left
    assert(queueRaw.size_approx() == 0);
    assert(queueParsed.size_approx() == 0);
    assert(queueSorted.size_approx() == 0);
    assert(queueCompressed.size_approx() == 0);
    assert(queueFiles.size_approx() == 0);

    return 0;
}