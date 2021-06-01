#include <cstdlib>
#include <iostream>
#include <dirent.h>
#include <fstream>
#include <mutex>

#include <pcapplusplus/PcapFileDevice.h>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>

#include "Model/CompressedBucket.h"
#include "Model/MetaBucket.h"
#include "Model/Filter.h"
#include "Converter/Converter.h"
#include "ConcurrentQueue/concurrentqueue.h"

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

inline void makeIcmpPacket(const IPTuple &t, unsigned char *icmp) {
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

inline void makeUdpPacket(const IPTuple &t, unsigned char *udp) {
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

inline void makeTcpPacket(const IPTuple &t, unsigned char *tcp) {
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

std::atomic<bool> readingFinished{false};
std::atomic<bool> filterCompressedBucketsFinished{false};
std::atomic<bool> filterIpTuplesFinished{false};
std::atomic<bool> writePcapFile{false};

void readFiles(const std::string &filePath, const std::vector<std::string> &files,
               moodycamel::ConcurrentQueue<MetaBucket> &outQueue) {
    for (const auto &file : files) {
        MetaBucket b;
        std::string fileName = filePath + file;
        std::ifstream ifs(fileName);
        boost::archive::binary_iarchive ia(ifs);
        ia >> b;
        outQueue.enqueue(b);
    }
    readingFinished = true;
}

void
filterCompressedBuckets(const filter::TimeRangePreFilter &timeRangePreFilter, const filter::IpPreFilter &ipPreFilter,
                        moodycamel::ConcurrentQueue<MetaBucket> &inQueue,
                        moodycamel::ConcurrentQueue<CompressedBucket> &outQueue) {
    while (!readingFinished || inQueue.size_approx() != 0) {
        MetaBucket m;
        if (inQueue.try_dequeue(m)) {
            for (const CompressedBucket &c : m.getStorage()) {
                if (timeRangePreFilter.apply(c.getMinTimestampAsInt(), c.getMaxTimestampAsInt()) &&
                    ipPreFilter.apply(c.getDict(), c.getFirstEntry().v4Src, c.getFirstEntry().v4Dst)) {
                    outQueue.enqueue(c);
                }
            }
        }
    }
    filterCompressedBucketsFinished = true;
}

void filterIpTuples(const filter::AndFilter &filter, moodycamel::ConcurrentQueue<CompressedBucket> &inQueue,
                    moodycamel::ConcurrentQueue<IPTuple> &outQueue) {
    while (!filterCompressedBucketsFinished || inQueue.size_approx() != 0) {
        CompressedBucket c;
        if (inQueue.try_dequeue(c)) {
            std::vector<IPTuple> decompressed{};
            c.getData(decompressed);
            for (const IPTuple &t : decompressed) {
                if (filter.apply(t)) {
                    outQueue.enqueue(t);
                }
            }
        }
    }
    filterIpTuplesFinished = true;
}

void writeToPcapFile(const std::string &filePath, const std::string &fileName,
                     moodycamel::ConcurrentQueue<IPTuple> &inQueue) {

    pcap_t *handle = pcap_open_dead(DLT_RAW,
                                    1 << 16); //second parameter is snapshot length, not relevant as set by caplen
    pcap_dumper_t *dumper = pcap_dump_open(handle, (filePath + fileName).c_str());


    while (!filterIpTuplesFinished || inQueue.size_approx() != 0) {
        IPTuple t;

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
    writePcapFile = true;
}


int main(int argc, char *argv[]) {
//    std::string filePath = "/home/ubuntu/testfiles/dir-1-3/";  // (1031565 packets)  (with payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-1-6/";  // (27013768 packets)  (no payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-6-7/";  // (107555567 packets) (no payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-mini/";  // (107555567 packets) (no payload)


    /// parsing arguments
    std::string filePath = "./";//default directory
    std::string filterString{};

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0) { // input directory specified
            filePath = argv[++i];
            if (filePath.at(filePath.size() - 1) != '/') {
                filePath.append("/");
            }
        }
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "-filter") == 0) { // filterString specified
            ++i;
            while (i < argc && argv[i][0] != '-') { //everything until next parameter (starts with '-') is filterString
                filterString.append(argv[i]).append(" ");
                ++i;
            }
        }
    }
    std::cout << "Reading from directory: " + filePath << std::endl;


    ///reading files form directory
    auto files = getFiles(filePath.c_str());
    if (files.empty()) {
        std::cout << "No Files found - exiting\n";
        exit(0);
    }

    auto start = std::chrono::high_resolution_clock::now();

    filter::AndFilter query{};
    filter::parseFilter(filterString, query);
    std::cout << "Applying Filter: " << query.toString() << std::endl;

    filter::TimeRangePreFilter timeRangePreFilter = filter::makeTimeRangePreFilter(filterString);
    filter::IpPreFilter ipPreFilter = filter::makeIpPreFilter(filterString);

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

    std::cout << "Reading from Files: " << "\n";
    for (auto x : files) {
        std::cout << "  " << x << "\n";
    }

    moodycamel::ConcurrentQueue<MetaBucket> metaBuckets2(500);
    moodycamel::ConcurrentQueue<CompressedBucket> compressedBuckets2(50000);
    moodycamel::ConcurrentQueue<IPTuple> ipTuples(500000);

    std::thread readerThread{readFiles, std::ref(filePath), std::ref(files), std::ref(metaBuckets2)};
    readerThread.join(); //queue is very slow for huge files TODO batch enqeuing of compressed buckets

    std::thread filterCBThread{filterCompressedBuckets, std::ref(timeRangePreFilter), std::ref(ipPreFilter),
                               std::ref(metaBuckets2), std::ref(compressedBuckets2)};
    std::thread filterIpThread{filterIpTuples, std::ref(query), std::ref(compressedBuckets2), std::ref(ipTuples)};

    auto end1 = std::chrono::high_resolution_clock::now();

    std::string fileName = query.toString() + ".pcap";
    std::thread writerThread{writeToPcapFile, std::ref(filePath), std::ref(fileName), std::ref(ipTuples)};


    filterCBThread.join();
    filterIpThread.join();
    writerThread.join();

    auto end2 = std::chrono::high_resolution_clock::now();
    auto durationNoWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end1 - start).count();
    auto durationWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - start).count();

    std::cout << "\nduration no write: \t\t" << durationNoWrite << " nanoseconds\n";
    std::cout << "\nduration w/ write: \t\t" << durationWrite << " nanoseconds\n";

    return 0;
}