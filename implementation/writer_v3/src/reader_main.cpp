#include <cstdlib>
#include <iostream>
#include <dirent.h>
#include <fstream>
#include <mutex>

#include <pcapplusplus/PcapFileDevice.h>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>

#include "Common/CompressedBucket.h"
#include "Common/MetaBucket.h"
#include "Reader/Filter.h"
#include "Common/ConcurrentQueue/concurrentqueue.h"

#define MINICMPHEADERLENGTH 20
#define MINICMPPKTLENGTH 21

#define MINUDPHEADERLENGTH 24
#define MINUDPPKTLENGTH 26

#define MINTCPHEADERLENGTH 24
#define MINTCPPKTLENGTH 28


std::vector<std::string> getFiles(const char *path) {
    struct dirent *entry;
    DIR *dir = opendir(path);

    if (dir == nullptr) {
        std::cout << "dir is null" << std::endl;
        return {};
    }
    std::vector<std::string> files{};
    while ((entry = readdir(dir)) != nullptr) {
        std::string filename = entry->d_name;
        if (filename.length() == 37 && filename.substr(33, 36) == ".bin" && filename.at(16) == '-') {
            files.push_back(filename);
        }
    }
    closedir(dir);
    return files;
}

inline void makeIcmpPacket(const common::IPTuple &t, unsigned char *icmp) {
    icmp[0] = 0x45; //declare as IPv4 Packet
    icmp[9] = 0x01; //declare next layer as icmp

    uint32_t srcAddrInt = t.getV4Src();
    unsigned char srcAddrBytes[4];
    memcpy(srcAddrBytes, &srcAddrInt, sizeof(srcAddrBytes));

    uint32_t dstAddrInt = t.getV4Dst();
    unsigned char dstAddrBytes[4];
    memcpy(dstAddrBytes, &dstAddrInt, sizeof(dstAddrBytes));

    icmp[12] = srcAddrBytes[0];
    icmp[13] = srcAddrBytes[1];
    icmp[14] = srcAddrBytes[2];
    icmp[15] = srcAddrBytes[3];

    icmp[16] = dstAddrBytes[0];
    icmp[17] = dstAddrBytes[1];
    icmp[18] = dstAddrBytes[2];
    icmp[19] = dstAddrBytes[3];
}

inline void makeUdpPacket(const common::IPTuple &t, unsigned char *udp) {
    udp[0] = 0x45; //declare as IPv4 Packet
    udp[9] = 0x11; //declare next layer as udp

    uint32_t srcAddrInt = t.getV4Src();
    unsigned char srcAddrBytes[4];
    memcpy(srcAddrBytes, &srcAddrInt, sizeof(srcAddrBytes));

    uint32_t dstAddrInt = t.getV4Dst();
    unsigned char dstAddrBytes[4];
    memcpy(dstAddrBytes, &dstAddrInt, sizeof(dstAddrBytes));

    udp[12] = srcAddrBytes[0];
    udp[13] = srcAddrBytes[1];
    udp[14] = srcAddrBytes[2];
    udp[15] = srcAddrBytes[3];

    udp[16] = dstAddrBytes[0];
    udp[17] = dstAddrBytes[1];
    udp[18] = dstAddrBytes[2];
    udp[19] = dstAddrBytes[3];

    uint16_t srcPortInt = t.getPortSrc();
    unsigned char srcPortBytes[2];
    srcPortBytes[0] = (srcPortInt >> 8) & 0xFF;
    srcPortBytes[1] = (srcPortInt) & 0xFF;

    uint16_t dstPortInt = t.getPortDst();
    unsigned char dstPortBytes[2];
    dstPortBytes[0] = (dstPortInt >> 8) & 0xFF;
    dstPortBytes[1] = (dstPortInt) & 0xFF;

    udp[20] = srcPortBytes[0];
    udp[21] = srcPortBytes[1];

    udp[22] = dstPortBytes[0];
    udp[23] = dstPortBytes[1];
}

inline void makeTcpPacket(const common::IPTuple &t, unsigned char *tcp) {
    tcp[0] = 0x45; //declare as IPv4 Packet
    tcp[9] = 0x06; //declare next layer as TCP

    uint32_t srcAddrInt = t.getV4Src();
    unsigned char srcAddrBytes[4];
    memcpy(srcAddrBytes, &srcAddrInt, sizeof(srcAddrBytes));

    uint32_t dstAddrInt = t.getV4Dst();
    unsigned char dstAddrBytes[4];
    memcpy(dstAddrBytes, &dstAddrInt, sizeof(dstAddrBytes));

    tcp[12] = srcAddrBytes[0];
    tcp[13] = srcAddrBytes[1];
    tcp[14] = srcAddrBytes[2];
    tcp[15] = srcAddrBytes[3];

    tcp[16] = dstAddrBytes[0];
    tcp[17] = dstAddrBytes[1];
    tcp[18] = dstAddrBytes[2];
    tcp[19] = dstAddrBytes[3];

    uint16_t srcPortInt = t.getPortSrc();
    unsigned char srcPortBytes[2];
    srcPortBytes[0] = (srcPortInt >> 8) & 0xFF;
    srcPortBytes[1] = (srcPortInt) & 0xFF;

    uint16_t dstPortInt = t.getPortDst();
    unsigned char dstPortBytes[2];
    dstPortBytes[0] = (dstPortInt >> 8) & 0xFF;
    dstPortBytes[1] = (dstPortInt) & 0xFF;

    tcp[20] = srcPortBytes[0];
    tcp[21] = srcPortBytes[1];

    tcp[22] = dstPortBytes[0];
    tcp[23] = dstPortBytes[1];
}

std::mutex readerStatusMutex;
std::mutex filterStatusMutex;
std::atomic<bool> readingFinished{false};
std::atomic<bool> filterCompressedBucketsFinished{false};
std::atomic<bool> filterIpTuplesFinished{false};


void readAndFilter(std::vector<bool> &status, const int &threadID, const std::string &filePath,
                   std::vector<std::string>::const_iterator startIt,
                   const std::vector<std::string>::const_iterator &endIt,
                   const reader::TimeRangePreFilter &timeRangePreFilter, const reader::IpPreFilter &ipPreFilter,
                   moodycamel::ConcurrentQueue<common::CompressedBucket> &outQueue) {

    for (; startIt < endIt; ++startIt) {
        common::MetaBucket m;
        std::string fileName = filePath + *startIt;
        std::ifstream ifs(fileName);
        boost::archive::binary_iarchive ia(ifs);
        ia >> m;
        std::vector<common::CompressedBucket> temp{};
        temp.reserve(1000000);
        for (const common::CompressedBucket &c : m.getStorage()) {
            if (timeRangePreFilter.apply(c.getMinTimestampAsInt(), c.getMaxTimestampAsInt()) &&
                ipPreFilter.apply(c.getDict(), c.getFirstEntry().v4Src, c.getFirstEntry().v4Dst)) {
                temp.emplace_back(c);
            }
        }
        outQueue.enqueue_bulk(temp.begin(), temp.size());
    }
    {
        std::lock_guard<std::mutex> lock(readerStatusMutex);
        status.at(threadID) = true;
        if (std::find(status.begin(), status.end(), false) ==
            status.end()) {  //false cannot be found -> all other threads are finished
            filterCompressedBucketsFinished = true;
        }
    }

}

void filterIpTuples(std::vector<bool> &status, const int &threadID, const reader::AndFilter &filter,
                    moodycamel::ConcurrentQueue<common::CompressedBucket> &inQueue,
                    moodycamel::ConcurrentQueue<common::IPTuple> &outQueue) {

    while (!filterCompressedBucketsFinished || inQueue.size_approx() != 0) {
        common::CompressedBucket c;
        std::vector<common::IPTuple> temp{};

        if (inQueue.try_dequeue(c)) {
            std::vector<common::IPTuple> decompressed{};
            c.getData(decompressed);
            temp.reserve(decompressed.size());
            for (const common::IPTuple &t : decompressed) {
                if (filter.apply(t)) {
                    temp.emplace_back(t);
                }
            }
            outQueue.enqueue_bulk(temp.begin(), temp.size());
            temp.clear();
        }
    }
    {
        std::lock_guard<std::mutex> lock(filterStatusMutex);
        status.at(threadID) = true;
        if (std::find(status.begin(), status.end(), false) ==
            status.end()) {  //false cannot be found -> all other threads are finished
            filterIpTuplesFinished = true;
        }
    }
}

void writeToPcapFile(const std::string filePath, const std::string fileName,
                     moodycamel::ConcurrentQueue<common::IPTuple> &inQueue) {

    pcap_t *handle = pcap_open_dead(DLT_RAW,
                                    1 << 16); //second parameter is snapshot length, not relevant as set by caplen
    std::string completeName = (filePath + fileName);
    pcap_dumper_t *dumper = pcap_dump_open(handle, completeName.c_str());

    while (!filterIpTuplesFinished || inQueue.size_approx() != 0) {
        common::IPTuple t;

        if (inQueue.try_dequeue(t)) {
            if (t.getProtocol() == 6) {
                unsigned char tcpPacket[MINTCPHEADERLENGTH] = {0x00};
                makeTcpPacket(t, tcpPacket);

                struct pcap_pkthdr pcap_hdr{};
                pcap_hdr.caplen = MINTCPHEADERLENGTH; //captured length
                pcap_hdr.len = t.getLength();// >= MINTCPPKTLENGTH ? t.getLength() : MINTCPPKTLENGTH;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
                pcap_hdr.ts.tv_sec = t.getTvSec();
                pcap_hdr.ts.tv_usec = t.getTvUsec();

                pcap_dump((u_char *) dumper, &pcap_hdr, tcpPacket);
            } else if (t.getProtocol() == 17) {
                unsigned char udpPacket[MINUDPHEADERLENGTH] = {0x00};
                makeUdpPacket(t, udpPacket);

                struct pcap_pkthdr pcap_hdr{};
                pcap_hdr.caplen = MINUDPHEADERLENGTH; //captured length
                pcap_hdr.len = t.getLength();//MINUDPPKTLENGTH;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
                pcap_hdr.ts.tv_sec = t.getTvSec();
                pcap_hdr.ts.tv_usec = t.getTvUsec();

                pcap_dump((u_char *) dumper, &pcap_hdr, udpPacket);
            } else if (t.getProtocol() == 1) {
                unsigned char icmpPacket[MINICMPHEADERLENGTH] = {0x00};
                makeIcmpPacket(t, icmpPacket);

                struct pcap_pkthdr pcap_hdr{};
                pcap_hdr.caplen = MINICMPHEADERLENGTH; //captured length
                pcap_hdr.len = t.getLength();//MINICMPPKTLENGTH;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
                pcap_hdr.ts.tv_sec = t.getTvSec();
                pcap_hdr.ts.tv_usec = t.getTvUsec();

                pcap_dump((u_char *) dumper, &pcap_hdr, icmpPacket);
            } else {
                assert(false);
            }
        }
    }
    pcap_dump_close(dumper);
}

inline void join(std::vector<std::thread> &threads) {
    if (!threads.empty()) {
        for (std::thread &t : threads) {
            t.join();
        }
    }
}

#define READER_THREADS 4
#define FILTER_THREADS 4

int main(int argc, char *argv[]) {
    /// parsing arguments
    std::string inFilePath = "./";//default directory
    std::string outFilePath = "./";//default directory
    std::string filterString{};
    bool writePcap = false;
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
        }
    }
    std::cout << "Reading from directory: " + inFilePath << std::endl;
    if (writePcap) {
        std::cout << "Writing to Pcap file at: " << outFilePath << std::endl;
    }

    ///reading files form directory
    auto files = getFiles(inFilePath.c_str());
    if (files.empty()) {
        std::cout << "No Files found - exiting\n";
        exit(0);
    }

    ///parsing filters
    reader::AndFilter query{};
    reader::parseFilter(filterString, query);
    std::cout << "Applying Filter: " << query.toString() << std::endl;

    auto start = std::chrono::high_resolution_clock::now();

    reader::TimeRangePreFilter timeRangePreFilter = reader::makeTimeRangePreFilter(filterString);
    reader::IpPreFilter ipPreFilter = reader::makeIpPreFilter(filterString);

    ///applying prefilter to only read neccessary files
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

    moodycamel::ConcurrentQueue<common::CompressedBucket> compressedBuckets2(2000000);
    moodycamel::ConcurrentQueue<common::IPTuple> ipTuples(1000000);

    std::vector<std::thread> readers{};
    readers.reserve(files.size());
    size_t readingThreadCount = READER_THREADS;
    ///prevents that more threads than files exist, in which case the threadcount is reduced
    if (files.size() < readingThreadCount) {
        readingThreadCount = files.size();
    }
    std::vector<bool> readerStatus(readingThreadCount, false);

    ///splitting files among multiple threads
    for (size_t i = 0; i < readingThreadCount; ++i) {
        if (i == 0) {
            std::vector<std::string>::const_iterator startIt = files.begin();
            std::vector<std::string>::const_iterator endIt =
                    files.begin() + files.size() % readingThreadCount + (files.size() / readingThreadCount);
            readers.emplace_back(readAndFilter, std::ref(readerStatus), i, std::ref(inFilePath), startIt, endIt,
                                 std::ref(timeRangePreFilter), std::ref(ipPreFilter), std::ref(compressedBuckets2));
        } else {
            auto startIt =
                    files.begin() + files.size() % readingThreadCount + (i * (files.size() / readingThreadCount));
            auto endIt =
                    files.begin() + files.size() % readingThreadCount + ((i + 1) * (files.size() / readingThreadCount));
            readers.emplace_back(readAndFilter, std::ref(readerStatus), i, std::ref(inFilePath), startIt, endIt,
                                 std::ref(timeRangePreFilter), std::ref(ipPreFilter), std::ref(compressedBuckets2));
        }
    }


    std::vector<std::thread> filters{};
    filters.reserve(FILTER_THREADS);
    std::vector<bool> filterStatus(FILTER_THREADS, false);
    for (int i = 0; i < FILTER_THREADS; ++i) {
        filters.emplace_back(
                std::thread{filterIpTuples, std::ref(filterStatus), i, std::ref(query), std::ref(compressedBuckets2),
                            std::ref(ipTuples)});
    }


    std::vector<std::thread> writers{};
    if (writePcap) {
        writers.reserve(1);
        std::string fileName = query.toString() + ".pcap";
        writers.emplace_back(writeToPcapFile, outFilePath, fileName, std::ref(ipTuples));
    }

    join(readers);
    join(filters);

    auto end1 = std::chrono::high_resolution_clock::now();

    join(writers);

    auto end2 = std::chrono::high_resolution_clock::now();
    auto durationNoWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end1 - start).count();
    auto durationWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - start).count();

    std::cout << "Read from Files: " << "\n";
    for (const auto &x : files) {
        std::cout << "  " << x << "\n";
    }

    std::cout << "\nduration no write: \t\t" << durationNoWrite << " nanoseconds\n";
    std::cout << "\nduration w/ write: \t\t" << durationWrite << " nanoseconds\n";

    return 0;
}