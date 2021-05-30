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


#define MINICMPHEADERLENGTH 20
#define MINICMPPKTLENGTH 21

#define MINUDPHEADERLENGTH 24
#define MINUDPPKTLENGTH 26

#define MINTCPHEADERLENGTH 24
#define MINTCPPKTLENGTH 28


int main(int argc, char *argv[]) {
//    std::string filePath = "/home/ubuntu/testfiles/dir-1-3/";  // (1031565 packets)  (with payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-1-6/";  // (27013768 packets)  (no payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-6-7/";  // (107555567 packets) (no payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-mini/";  // (107555567 packets) (no payload)
    std::string filePath = "./";//default directory
    std::string filterString{};

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0) { // input directory specified
            filePath = argv[++i];
            if (filePath.at(filePath.size() - 1) != '/') {
                filePath.append("/");
            }
        }
        if (strcmp(argv[i], "-f") == 0) { // filterString specified
            ++i;
            while (i < argc && argv[i][0] != '-') { //everything until next parameter (starts with '-') is filterString
                filterString.append(argv[i]).append(" ");
                ++i;
            }
        }
    }
    std::cout << "Reading from directory: " + filePath << std::endl;

    auto files = getFiles(filePath.c_str());
    if (files.empty()) {
        std::cout << "No Files found - exiting\n";
        exit(0);
    }

    auto start = std::chrono::high_resolution_clock::now();

    filter::AndFilter myFilter{};
    parseFilter(filterString, myFilter);
    std::cout << "Applying Filter: " << myFilter.toString() << std::endl;

    filter::TimeRangeFilter timeRangeFilter = filter::makeTimerangeFilter(filterString);//  timeRangeFilter{};
    std::cout << timeRangeFilter.toString() << std::endl;

    auto end0 = std::chrono::high_resolution_clock::now();


    for (size_t i = 0; i < files.size();) {
        std::string name = files.at(i);
        uint8_t midIndex = name.find('-');
        uint8_t endIndex = name.find('.');
        uint64_t fromTime = std::stoll(name.substr(0, midIndex));
        uint64_t toTime = std::stoll(name.substr(midIndex + 1, endIndex - midIndex - 1));
        if (!timeRangeFilter.apply(fromTime, toTime)) {
            files.erase(files.begin() + i);
        } else {
            ++i;
        }
    }

    std::cout << "Reading from Files: " << "\n";
    for (auto x : files) {
        std::cout << "  " << x << "\n";
    }

    std::vector<MetaBucket> metaBuckets{};
    {
        for (const auto &file : files) {
            MetaBucket b;
            std::string fileName = filePath + file;
            std::ifstream ifs(fileName);
            boost::archive::binary_iarchive ia(ifs);
            ia >> b;
            metaBuckets.push_back(b);
        }
    }

    std::vector<CompressedBucket> compressedBuckets{};
    //TODO check if compressedbucket contains ip address if queried
    for (auto m : metaBuckets) {
        for (const CompressedBucket &c : m.getStorage()) {
            if (timeRangeFilter.apply(c.getMinTimestampAsInt(), c.getMaxTimestampAsInt())) {
                compressedBuckets.push_back(c);
            }
        }
    }

    //TODO filterString before conversion to IPTuple, make decision on Entries
    std::vector<IPTuple> tuples{};
    for (auto c : compressedBuckets) {
        std::vector<IPTuple> temp{};
        c.getData(temp);
        tuples.insert(tuples.end(), temp.begin(), temp.end());
    }
    auto end1 = std::chrono::high_resolution_clock::now();


    pcap_t *handle = pcap_open_dead(DLT_RAW, 1
            << 16); //second parameter is snapshot length, i think not relevant as set by caplen
    pcap_dumper_t *dumper = pcap_dump_open(handle, (filePath + "cap.pcap").c_str());
    size_t packetCounter = 0;

    for (IPTuple t : tuples) {
        ++packetCounter;
        if (myFilter.apply(t)) {
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

    auto end2 = std::chrono::high_resolution_clock::now();
    auto durationNoWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end1 - start).count();
    auto durationWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - start).count();
    auto durationParseFilter = std::chrono::duration_cast<std::chrono::nanoseconds>(end0 - start).count();

    std::cout << "\nPacket Count: " << packetCounter << std::endl;
    std::cout<< "Filter Parsing Duration: "<<durationParseFilter<<"\n";
    if (packetCounter != 0) {
        std::cout << "Duration no write: \t\t" << durationNoWrite << " nanoseconds, Handling time per packet: "
                  << durationNoWrite / packetCounter << "; Packets per second: "
                  << 1000000000 / (durationNoWrite / packetCounter) << "\n";
        std::cout << "Duration w/ write: \t\t" << durationWrite << " nanoseconds, Handling time per packet: "
                  << durationWrite / packetCounter << "; Packets per second: "
                  << 1000000000 / (durationWrite / packetCounter) << "\n";
    }
    return 0;
}