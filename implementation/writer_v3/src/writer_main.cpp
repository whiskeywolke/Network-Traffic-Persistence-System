#include <cstdlib>
#include <iostream>
#include <memory>
#include <thread>
#include <fstream>
#include <mutex>

#include "Common/ConcurrentQueue/concurrentqueue.h"
#include "Common/IPTuple.h"
#include "Common/CompressedBucket.h"
#include "Common/MetaBucket.h"
#include "Common/Directory.h"

#include "Writer/ThreadOperations/ReaderThread.h"
#include "Writer/ThreadOperations/ConverterThread.h"
#include "Writer/ThreadOperations/SorterThread.h"
#include "Writer/ThreadOperations/CompressorThread.h"
#include "Writer/ThreadOperations/AggregatorThread.h"
#include "Writer/ThreadOperations/WriterThread.h"
#include "Writer/ThreadOperations/LiveCaptureThread.h"


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

    ///checking that total number of threads does not supersede pyhsical thread count for maximum performance
    if ((READER_THREADS + CONVERTER_THREADS + SORTER_THREADS + COMPRESSOR_THREADS + AGGREGATOR_THREADS +
         WRITER_THREADS) > std::thread::hardware_concurrency()) {
        std::cout << "REQUESTED MORE THREADS THAN SUPPORTED, PERFORMANCE MAY NOT BE OPTIMAL (supported: "
                  << std::thread::hardware_concurrency()
                  << ", requested: "
                  << (READER_THREADS + CONVERTER_THREADS + SORTER_THREADS + COMPRESSOR_THREADS + AGGREGATOR_THREADS +
                      WRITER_THREADS) << ")" << std::endl;
    }

    ///flags set by arguments
    std::string outFilePath = "./"; //default directory
    std::string inFilename;
    std::string deviceName = "";
    bool fileCapture = false;
    bool liveCapture = false;
    bool sequentialExecution = false;

    ///parsing arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-o") == 0) { // output directory specified
            outFilePath = argv[++i];
            if (outFilePath.at(outFilePath.size() - 1) != '/') {
                outFilePath.append("/");
            }
        } else if (strcmp(argv[i], "-fI") == 0) { //using hardcoded predefined fileCapture
            inFilename = inputFiles.at(atoi(argv[++i]));
            fileCapture = true;
        } else if (strcmp(argv[i], "-f") == 0) {
            inFilename = argv[++i];
            fileCapture = true;
        } else if (strcmp(argv[i], "-s") == 0) {
            sequentialExecution = true;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "-live") == 0) {
            liveCapture = true;
            deviceName = argv[++i];
        }
    }
    ///printing configuration
    if (sequentialExecution) {
        std::cout << "WARNING: Running in sequential mode\n";
    }
    if (fileCapture) {
        std::cout << "Reading from file: " << inFilename << "\n";
    } else if (liveCapture) {
        std::cout << "Capturing from device: " << deviceName << "\n";
    } else {
        std::cout << "no file or device to read from specified, exiting now\n";
        return 0;
    }
    std::cout << "Writing to directory: " + outFilePath << "\n";

    ///vectors storing worker threads
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

    ///boolean vectors for synchronization of threads
    std::vector<bool> readerStatus(READER_THREADS, false);
    std::vector<bool> converterStatus(CONVERTER_THREADS, false);
    std::vector<bool> sorterStatus(SORTER_THREADS, false);
    std::vector<bool> compressorStatus(COMPRESSOR_THREADS, false);
    std::vector<bool> aggregatorStatus(AGGREGATOR_THREADS, false);
    std::vector<bool> writerStatus(WRITER_THREADS, false);

    ///status_mutex prevents concurrent access to the status vectors
    std::mutex readerStatus_mutex;
    std::mutex converterStatus_mutex;
    std::mutex sorterStatus_mutex;
    std::mutex compressorStatus_mutex;
    std::mutex aggregatorStatus_mutex;

    ///flag shows that all threads finished working at one stage of the problem
    std::atomic<bool> readingFinished{false};
    std::atomic<bool> conversionFinished{false};
    std::atomic<bool> sortingFinished{false};
    std::atomic<bool> compressionFinished{false};
    std::atomic<bool> aggregationFinished{false};

    ///queues for data synchronization
    moodycamel::ConcurrentQueue<pcpp::RawPacket> queueRaw(10000000);
    moodycamel::ConcurrentQueue<common::IPTuple> queueParsed(10000000);
    moodycamel::ConcurrentQueue<std::vector<common::IPTuple>> queueSorted(50000);
    moodycamel::ConcurrentQueue<common::CompressedBucket> queueCompressed(50000);
    moodycamel::ConcurrentQueue<common::MetaBucket> queueFiles(50000);

    ///statistics
    std::atomic<long> readPackets{0};
    std::atomic<long> readingDuration{0};
    std::atomic<long> conversionDuration{0};
    std::atomic<long> sortingDuration{0};
    std::atomic<long> compressionDuration{0};
    std::atomic<long> aggregationDuration{0};
    std::atomic<long> writingDuration{0};


    auto start = std::chrono::high_resolution_clock::now();

///for profiling call all functions sequential in main thread
/*
    readPcapFile(std::ref(inFilename), &queueRaw);
    convert(&queueRaw, &queueParsed);
    sortSingleThread(&queueParsed, &queueSorted);
    compress(&queueSorted, &queueCompressed);
*/

    ///creating threads
    for (int i = 0; i < READER_THREADS; ++i) {
        if (!liveCapture) {
            readers.emplace_back(writer::threadOperations::readPcapFile, std::ref(inFilename), &readerStatus, i,
                                 &queueRaw, std::ref(readerStatus_mutex),
                                 std::ref(readingFinished), std::ref(readingDuration), std::ref(readPackets));
        } else {
            readers.emplace_back(writer::threadOperations::readLiveDevice, std::ref(deviceName), &readerStatus, i,
                                 &queueRaw, std::ref(readerStatus_mutex),
                                 std::ref(readingFinished), std::ref(readingDuration), std::ref(readPackets));
        }
    }
    if (sequentialExecution) { join(readers); }

    for (int i = 0; i < CONVERTER_THREADS; ++i) {
        converters.emplace_back(writer::threadOperations::convert, &converterStatus, i, &queueRaw, &queueParsed,
                                std::ref(converterStatus_mutex),
                                std::ref(readingFinished), std::ref(conversionFinished), std::ref(conversionDuration));
    }
    if (sequentialExecution) { join(converters); }

    for (int i = 0; i < SORTER_THREADS; ++i) {
        sorters.emplace_back(writer::threadOperations::sortSingleThread, &sorterStatus, i, &queueParsed, &queueSorted,
                             std::ref(sorterStatus_mutex),
                             std::ref(conversionFinished), std::ref(sortingFinished), std::ref(sortingDuration));
    }
    if (sequentialExecution) { join(sorters); }

    for (int i = 0; i < COMPRESSOR_THREADS; ++i) {
        compressors.emplace_back(writer::threadOperations::compress, &compressorStatus, i, &queueSorted,
                                 &queueCompressed, std::ref(compressorStatus_mutex),
                                 std::ref(sortingFinished), std::ref(compressionFinished),
                                 std::ref(compressionDuration));
    }
    if (sequentialExecution) { join(compressors); }

    for (int i = 0; i < AGGREGATOR_THREADS; ++i) {
        aggregators.emplace_back(writer::threadOperations::aggregate, &aggregatorStatus, i, &queueCompressed,
                                 &queueFiles, std::ref(aggregatorStatus_mutex),
                                 std::ref(compressionFinished), std::ref(aggregationFinished),
                                 std::ref(aggregationDuration));
    }
    if (sequentialExecution) { join(aggregators); }

    for (int i = 0; i < WRITER_THREADS; ++i) {
        writers.emplace_back(writer::threadOperations::writeToFile, &writerStatus, i, &queueFiles, outFilePath,
                             std::ref(aggregationFinished),
                             std::ref(writingDuration));
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

    /// print results
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
    std::cout << "Total File size: " << common::getTotalFilesSize(outFilePath.c_str()) << " Bytes \n";
    std::cout << "Avg Bytes per Packet: " << (common::getTotalFilesSize(outFilePath.c_str()) + 0.0) / readPackets
              << " Bytes \n";

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