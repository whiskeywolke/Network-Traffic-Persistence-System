#include <cstdlib>
#include <pcapplusplus/PcapFileDevice.h>
#include <iostream>
#include "Converter/Converter.h"
#include "ConcurrentQueue/concurrentqueue.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>

#include "Model/CompressedBucket.h"
#include "Model/MetaBucket.h"
#include "Model/SortST.h"

#include <memory>
#include <thread>

#include <dirent.h>

#include <fstream>
#include <mutex>


#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/EthLayer.h>

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

int main(int argc, char* argv[]) {
//    std::string filePath = "/home/ubuntu/testfiles/dir-1-3/";  // (1031565 packets)  (with payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-1-6/";  // (27013768 packets)  (no payload)
//    std::string filePath = "/home/ubuntu/testfiles/dir-6-7/";  // (107555567 packets) (no payload)
    std::string filePath = "/home/ubuntu/testfiles/dir-mini/";  // (107555567 packets) (no payload)

    auto files = getFiles(filePath.c_str());
    std::vector<MetaBucket>metaBuckets{};
    {
        for(auto file : files) {
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

    std::cout<<tuples.size()<<std::endl;

    ////craft packets
    pcpp::PcapFileWriterDevice writer2((filePath + "1_new_packet.pcap").c_str());
    writer2.open();

    for(auto ipTuple : tuples){
        // ipTuple.

        pcpp::Packet newPacket(100);


        pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("00:00:00:00:00:00"), pcpp::MacAddress("00:00:00:00:00"));
        newPacket.addLayer(&newEthernetLayer);

        pcpp::IPv4Layer ipLayer(pcpp::IPv4Address(ipTuple.getV4Src()), pcpp::IPv4Address(ipTuple.getV4Dst()));
        newPacket.addLayer(&ipLayer);
        if(ipTuple.getProtocol() == 17) { //UDP
            pcpp::UdpLayer udpLayer(ipTuple.getPortSrc(), ipTuple.getPortDst());
            newPacket.addLayer(&udpLayer);
            udpLayer.computeCalculateFields();
        }
        else if(ipTuple.getProtocol() == 6) { //TCP
            pcpp::TcpLayer tcpLayer(ipTuple.getPortSrc(), ipTuple.getPortDst());
            newPacket.addLayer(&tcpLayer);
            tcpLayer.computeCalculateFields();
        }
        else if(ipTuple.getProtocol() == 1) { //ICMP
            pcpp::IcmpLayer icmpLayer{};
            newPacket.addLayer(&icmpLayer);
            icmpLayer.computeCalculateFields();
        }
        //newPacket.computeCalculateFields();

        ipLayer.computeCalculateFields();
        newEthernetLayer.computeCalculateFields();
        //  newPacket.getRawPacket();
        //  std::cout<<      newPacket.toString()<<std::endl;
        struct timeval ts;
        ts.tv_usec = ipTuple.getTvUsec();
        ts.tv_sec = ipTuple.getTvSec();
        newPacket.getRawPacket()->setPacketTimeStamp(ts);
        writer2.writePacket(*(newPacket.getRawPacket()));
    }
    writer2.close();

    return 0;
}