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
#include "Converter/Converter.h"
#include "ConcurrentQueue/concurrentqueue.h"


std::vector<std::string> getFiles(const char *path) {
    struct dirent *entry;
    DIR *dir = opendir(path);

    if (dir == NULL) {
        std::cout << "dir is null" << std::endl;
        return {};
    }
    std::vector<std::string>files{};
    while ((entry = readdir(dir)) != NULL) {
        std::string filename = entry->d_name;
        if(filename.length() == 37 && filename.substr(33,36) == ".bin" && filename.at(16) == '-'){
            files.push_back(filename);
        }
    }
    closedir(dir);
    return files;
}

inline void makeIcmpPacket(const IPTuple& t, unsigned char *icmp){
    icmp[0] = 0x45; //declare as IPv4 Packet
    icmp[9] = 0x01; //declare next layer as icmp

   // uint32_t srcAddrInt = t.getV4Src();
    uint32_t srcAddrInt = pcpp::IPv4Address("0.0.0.0").toInt();
    unsigned char srcAddrBytes[4];
    memcpy(srcAddrBytes, &srcAddrInt, sizeof(srcAddrBytes));

    // uint32_t srcAddrInt = t.getV4Src();
    uint32_t dstAddrInt = pcpp::IPv4Address("237.2.3.4").toInt(); //will be marked as invalid depending on address
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

inline void makeUdpPacket(const IPTuple& t, unsigned char *icmp) {
    icmp[0] = 0x45; //declare as IPv4 Packet
    icmp[9] = 0x11; //declare next layer as udp

    uint32_t srcAddrInt = t.getV4Src();
    //uint32_t srcAddrInt = pcpp::IPv4Address("0.0.0.0").toInt();
    unsigned char srcAddrBytes[4];
    memcpy(srcAddrBytes, &srcAddrInt, sizeof(srcAddrBytes));

    uint32_t dstAddrInt = t.getV4Dst();
    //uint32_t dstAddrInt = pcpp::IPv4Address("237.2.3.4").toInt(); //will be marked as invalid depending on address
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

    uint16_t srcPortInt = t.getPortSrc();
    unsigned char srcPortBytes[2];
    srcPortBytes[0] = (srcPortInt >> 8) & 0xFF;
    srcPortBytes[1] = (srcPortInt) & 0xFF;

    uint16_t dstPortInt = t.getPortDst();
    unsigned char dstPortBytes[2];
    dstPortBytes[0] = (dstPortInt >> 8) & 0xFF;
    dstPortBytes[1] = (dstPortInt) & 0xFF;

    icmp[20] = srcPortBytes[0];
    icmp[21] = srcPortBytes[1];

    icmp[22] = dstPortBytes[0];
    icmp[23] = dstPortBytes[1];
}

inline void makeTcpPacket(const IPTuple& t, unsigned char *icmp) {
    icmp[0] = 0x45; //declare as IPv4 Packet
    icmp[9] = 0x06; //declare next layer as TCP

    uint32_t srcAddrInt = t.getV4Src();
    //uint32_t srcAddrInt = pcpp::IPv4Address("0.0.0.0").toInt();
    unsigned char srcAddrBytes[4];
    memcpy(srcAddrBytes, &srcAddrInt, sizeof(srcAddrBytes));

    uint32_t dstAddrInt = t.getV4Dst();
    //uint32_t dstAddrInt = pcpp::IPv4Address("237.2.3.4").toInt(); //will be marked as invalid depending on address
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

    uint16_t srcPortInt = t.getPortSrc();
    unsigned char srcPortBytes[2];
    srcPortBytes[0] = (srcPortInt >> 8) & 0xFF;
    srcPortBytes[1] = (srcPortInt) & 0xFF;

    uint16_t dstPortInt = t.getPortDst();
    unsigned char dstPortBytes[2];
    dstPortBytes[0] = (dstPortInt >> 8) & 0xFF;
    dstPortBytes[1] = (dstPortInt) & 0xFF;

    icmp[20] = srcPortBytes[0];
    icmp[21] = srcPortBytes[1];

    icmp[22] = dstPortBytes[0];
    icmp[23] = dstPortBytes[1];
}

#define MINICMPHEADERLENGTH 20
#define MINICMPPKTLENGTH 21

#define MINUDPHEADERLENGTH 24
#define MINUDPPKTLENGTH 26

#define MINTCPHEADERLENGTH 24
#define MINTCPPKTLENGTH 28


int main(int argc, char* argv[]) {
//    std::string filePath = "/home/ubuntu/testfiles/dir-1-3/";  // (1031565 packets)  (with payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-1-6/";  // (27013768 packets)  (no payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-6-7/";  // (107555567 packets) (no payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-mini/";  // (107555567 packets) (no payload)
    std::string filePath = "./";//default directory

    for(int i = 1; i < argc; ++i){
        if(strcmp(argv[i], "-i") == 0){ // input directory specified
            filePath = argv[++i];
            if(filePath.at(filePath.size()-1) != '/'){
                filePath.append("/");
            }
        }
    }

    std::cout<<"Reading from directory: " + filePath<<std::endl;

    auto files = getFiles(filePath.c_str());

    auto start = std::chrono::high_resolution_clock::now();

    std::vector<MetaBucket>metaBuckets{};
    {
        for(const auto& file : files) {
            MetaBucket b;

            std::string fileName = filePath  + file;
            std::ifstream ifs(fileName);
            boost::archive::binary_iarchive ia(ifs);
            ia >> b;
            metaBuckets.push_back(b);
        }
    }

    std::vector<CompressedBucket>compressedBuckets{};

    for(auto m : metaBuckets){
        compressedBuckets.insert(compressedBuckets.end(), m.storage.begin(), m.storage.end());
    }

    std::vector<IPTuple>tuples{};
    for(auto c : compressedBuckets){
        std::vector<IPTuple>temp{};
        c.getData(temp);
        tuples.insert(tuples.end(), temp.begin(), temp.end());
    }
    auto end1 = std::chrono::high_resolution_clock::now();

    std::cout<<"tuples size:" <<tuples.size()<<std::endl;

//////////////////////////////////////////////

    pcap_t *handle = pcap_open_dead(DLT_RAW, 1 << 16); //second parameter is snapshot length, i think not relevant as set by caplen
    pcap_dumper_t *dumper = pcap_dump_open(handle, (filePath + "cap.pcap").c_str());

    for(IPTuple t : tuples){
        if(t.getProtocol() == 6){
            unsigned char tcpPacket[MINTCPHEADERLENGTH] = {0x00};
            makeTcpPacket(t, tcpPacket);

            struct pcap_pkthdr pcap_hdr{};
            pcap_hdr.caplen = MINTCPHEADERLENGTH; //captured length
            pcap_hdr.len = MINTCPPKTLENGTH;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
            pcap_hdr.ts.tv_sec = t.getTvSec();
            pcap_hdr.ts.tv_usec = t.getTvUsec();

            pcap_dump((u_char *) dumper, &pcap_hdr, tcpPacket);
        }else if(t.getProtocol() == 17){
            unsigned char udpPacket[MINUDPHEADERLENGTH] = {0x00};
            makeUdpPacket(t, udpPacket);

            struct pcap_pkthdr pcap_hdr{};
            pcap_hdr.caplen = MINUDPHEADERLENGTH; //captured length
            pcap_hdr.len = MINUDPPKTLENGTH;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
            pcap_hdr.ts.tv_sec = t.getTvSec();
            pcap_hdr.ts.tv_usec = t.getTvUsec();

            pcap_dump((u_char *) dumper, &pcap_hdr, udpPacket);
        }else if(t.getProtocol() == 1)    {
            unsigned char icmpPacket[MINICMPHEADERLENGTH] = {0x00};
            makeIcmpPacket(t, icmpPacket);

            struct pcap_pkthdr pcap_hdr{};
            pcap_hdr.caplen = MINICMPHEADERLENGTH; //captured length
            pcap_hdr.len = MINICMPPKTLENGTH;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
            pcap_hdr.ts.tv_sec = t.getTvSec();
            pcap_hdr.ts.tv_usec = t.getTvUsec();

            pcap_dump((u_char *) dumper, &pcap_hdr, icmpPacket);
        }else{
            assert(false);
        }
    }
    pcap_dump_close(dumper);
    auto end2 = std::chrono::high_resolution_clock::now();
    auto durationNoWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end1 - start).count();
    auto durationWrite = std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - start).count();
    std::cout << "\nduration no write: \t\t" << durationNoWrite << " nanoseconds\n";
    std::cout <<   "duration w/ write: \t\t" << durationWrite << " nanoseconds\n";

    return 0;
}