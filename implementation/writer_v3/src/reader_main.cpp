#include <cstdlib>
#include <iostream>
#include <dirent.h>
#include <fstream>
#include <mutex>

#include "Reader/ThreadOperations/ReaderThread.h"
#include "Reader/ThreadOperations/FilterThread.h"
#include "Reader/ThreadOperations/PcapWriterThread.h"
#include "Reader/ThreadOperations/OutThread.h"
#include "Reader/Filter.h"
#include "Reader/Aggregator.h"

#include "Common/ConcurrentQueue/concurrentqueue.h"
#include "Common/CompressedBucket.h"
#include "Common/Directory.h"

#define READER_THREADS 4
#define FILTER_THREADS 4

void aggregates(std::string config,  moodycamel::ConcurrentQueue <common::IPTuple> &inQueue, std::atomic<bool> &filterIpTuplesFinished){
    //parse config to
    //interval
    //operation
    //field (of IPtuple)

    //map<timeslot, vector<uint32>>  holds all vectors mapped by timeslots
    std::cout<<"hier\n";
  //  std::vector<uint32_t> temp{}; //holds one field of all IPTuples on which the operation is performed
    reader::Aggregator agg(reader::AggregationOperator::sum, reader::IpTupleField::length, 1000000);
    while (!filterIpTuplesFinished || inQueue.size_approx() != 0) {
        std::vector<common::IPTuple> temp{1000};

        size_t dequeued = inQueue.try_dequeue_bulk(temp.begin(), 1000);

        for(size_t i = 0; i < dequeued; ++i){
            agg.add(temp.at(i));
        }
    }
    auto x = agg.calculate();

    std::cout<<"size: "<<x.size()<<std::endl;
    for(const uint32_t& temp : x){
        std::cout<<temp<<std::endl;
    }

}

inline void join(std::vector<std::thread> &threads) {
    if (!threads.empty()) {
        for (std::thread &t : threads) {
            t.join();
        }
    }
}

int main(int argc, char *argv[]) {
    ///flags set by arguments
    std::string inFilePath = "./";//default directory
    std::string outFilePath = "./";//default directory
    std::string filterString{};
    bool writePcap = false;
    bool verbose = false;
    bool aggregate = false;

    /// parsing arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0) { // input directory specified
            inFilePath = argv[++i];
            if (inFilePath.at(inFilePath.size() - 1) != '/') {
                inFilePath.append("/");
            }
            if (outFilePath == "./") { //by default write to same directory as it is read from
                outFilePath = inFilePath;
            }
        } else if (strcmp(argv[i], "-o") == 0) {
            outFilePath = argv[++i];
            if (outFilePath.at(outFilePath.size() - 1) != '/') {
                outFilePath.append("/");
            }
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "-reader") == 0) { // filterString specified
            ++i;
            while (i < argc && argv[i][0] != '-') { //everything until next parameter (starts with '-') is filterString
                filterString.append(argv[i]).append(" ");
                ++i;
            }
            --i;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "-pcap") == 0) { // filterString specified
            writePcap = true;
        }else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "-verbose") == 0) { // filterString specified
            verbose = true;
        }else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "-aggregate") == 0) { // filterString specified
            aggregate = true;
        }
    }

    ///parsing filterThreads
    reader::AndFilter query{};
    reader::parseFilter(filterString, query);

    ///printing configuration
    if(verbose) {
        std::cout << "Reading from directory: " + inFilePath << std::endl;
        if (writePcap) {
            std::cout << "Writing to Pcap file at: " << outFilePath << std::endl;
        }
        std::cout << "Applying Filter: " << query.toString() << std::endl;
    }
    ///reading files form directory
    auto files = common::getFilesFromDir(inFilePath.c_str());
    if (files.empty()) {
        std::cout << "No Files found - exiting\n";
        exit(0);
    }

    auto start = std::chrono::high_resolution_clock::now();

    ///applying prefilter to only read necessary files
    reader::TimeRangePreFilter timeRangePreFilter = reader::makeTimeRangePreFilter(filterString);
    reader::IpPreFilter ipPreFilter = reader::makeIpPreFilter(filterString);

    for (size_t i = 0; i < files.size();) {
        std::string name = files.at(i);
        uint8_t midIndex = name.find('-');
        uint8_t endIndex = name.find('.');
        uint64_t fromTime = std::stoll(name.substr(0, midIndex));
        uint64_t toTime = std::stoll(name.substr(midIndex + 1, endIndex - midIndex - 1));
        if (!timeRangePreFilter.apply(fromTime, toTime)) {
            files.erase(files.begin() + i);
        } else {
            ++i;
        }
    }

    /// queues for data synchronization
    moodycamel::ConcurrentQueue<common::CompressedBucket> compressedBuckets(2000000);
    moodycamel::ConcurrentQueue<common::IPTuple> ipTuples(1000000);

    ///creating vectors holding threads
    std::vector<std::thread> readerThreads{};
    std::vector<std::thread> filterThreads{};
    std::vector<std::thread> outThreads{};

    size_t readingThreadCount = READER_THREADS;
    if (files.size() < readingThreadCount) {
        ///prevents that more threads than files exist, in which case the threadcount is reduced
        readingThreadCount = files.size();
    }
    readerThreads.reserve(readingThreadCount);
    filterThreads.reserve(FILTER_THREADS);

    ///boolean vectors for synchronization of threads
    std::vector<bool> readerStatus(readingThreadCount, false);
    std::vector<bool> filterStatus(FILTER_THREADS, false);

    ///status_mutex prevents concurrent access to the status vectors
    std::mutex readerStatusMutex;
    std::mutex filterStatusMutex;

    ///flag shows that all threads finished working at one stage of the problem
    std::atomic<bool> filterCompressedBucketsFinished{false};
    std::atomic<bool> filterIpTuplesFinished{false};


    ///creating threads
    for (size_t i = 0; i < readingThreadCount; ++i) {
        ///splitting files among multiple threads
        if (i == 0) {
            std::vector<std::string>::const_iterator startIt = files.begin();
            std::vector<std::string>::const_iterator endIt =
                    files.begin() + files.size() % readingThreadCount + (files.size() / readingThreadCount);
            readerThreads.emplace_back(reader::threadOperations::readAndFilter, std::ref(readerStatus), i, std::ref(inFilePath), startIt, endIt,
                                       std::ref(timeRangePreFilter), std::ref(ipPreFilter), std::ref(compressedBuckets), std::ref(readerStatusMutex), std::ref(filterCompressedBucketsFinished));
        } else {
            auto startIt =
                    files.begin() + files.size() % readingThreadCount + (i * (files.size() / readingThreadCount));
            auto endIt =
                    files.begin() + files.size() % readingThreadCount + ((i + 1) * (files.size() / readingThreadCount));
            readerThreads.emplace_back(reader::threadOperations::readAndFilter, std::ref(readerStatus), i, std::ref(inFilePath), startIt, endIt,
                                       std::ref(timeRangePreFilter), std::ref(ipPreFilter), std::ref(compressedBuckets), std::ref(readerStatusMutex), std::ref(filterCompressedBucketsFinished));
        }
    }

    for (int i = 0; i < FILTER_THREADS; ++i) {
        filterThreads.emplace_back(
                std::thread{reader::threadOperations::filterIpTuples, std::ref(filterStatus), i, std::ref(query), std::ref(compressedBuckets),
                            std::ref(ipTuples), std::ref(filterStatusMutex), std::ref(filterCompressedBucketsFinished), std::ref( filterIpTuplesFinished)});
    }

    if(!aggregate) {
        if (writePcap) {
            outThreads.reserve(1);
            std::string fileName = query.toString() + ".pcap";
            outThreads.emplace_back(reader::threadOperations::writeToPcapFile, outFilePath, fileName,
                                    std::ref(ipTuples), std::ref(filterIpTuplesFinished));
        } else {
            outThreads.emplace_back(reader::threadOperations::writeOut, std::ref(std::cout), std::ref(ipTuples),
                                    std::ref(filterIpTuplesFinished));
        }
    }else{
        //todo aggregate
        aggregates("asd",std::ref(ipTuples), std::ref(filterIpTuplesFinished));
    }

    join(readerThreads);
    join(filterThreads);

    auto end1 = std::chrono::high_resolution_clock::now();

    join(outThreads);

    auto end2 = std::chrono::high_resolution_clock::now();

    auto durationNoWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end1 - start).count();
    auto durationWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - start).count();


    ///printing statistics
    if(verbose) {
        std::cout << "Read from Files: " << "\n";
        for (const auto &x : files) {
            std::cout << "  " << x << "\n";
        }

        std::cout << "\nduration no write: \t\t" << durationNoWrite << " nanoseconds\n";
        std::cout << "\nduration w/ write: \t\t" << durationWrite << " nanoseconds\n";
    }
    return 0;
}