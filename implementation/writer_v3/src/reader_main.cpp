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
#include <pcapplusplus/RawPacket.h>

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

void makeIcmpPacket(const IPTuple& t, unsigned char *icmp){
   // for(int i = 0; i < 20; ++i){
   //     icmp[i] = 0x00;
   // }

    icmp[0] = 0x45; //declare as IPv4 Packet

    icmp[9] = 0x01; //declare next layer as icmp

//    auto srcAddrBytes = pcpp::IPv4Address(t.getV4Src()).toBytes();
    auto srcAddrBytes = pcpp::IPv4Address("0.0.0.0").toBytes();
//    auto dstAddrBytes = pcpp::IPv4Address(t.getV4Dst()).toBytes();
    auto dstAddrBytes = pcpp::IPv4Address("237.1.1.1").toBytes(); //will be marked as invalid depending on src address

    icmp[12] = srcAddrBytes[0];
    icmp[13] = srcAddrBytes[1];
    icmp[14] = srcAddrBytes[2];
    icmp[15] = srcAddrBytes[3];

    icmp[16] = dstAddrBytes[0];
    icmp[17] = dstAddrBytes[1];
    icmp[18] = dstAddrBytes[2];
    icmp[19] = dstAddrBytes[3];
}


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

    std::cout<<"tuples size:" <<tuples.size()<<std::endl;

/*    ////craft packets
    pcpp::PcapFileWriterDevice writer2((filePath + "1_new_packet.pcap").c_str(),  pcpp::LINKTYPE_IPV4);
    writer2.open();

    for(auto ipTuple : tuples){
        // ipTuple.

        pcpp::Packet newPacket(100);

       // pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("00:00:00:00:00:00"), pcpp::MacAddress("00:00:00:00:00"));
        //newPacket.addLayer(&newEthernetLayer);

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
        ipLayer.getNextLayer();

        //newEthernetLayer.computeCalculateFields();
        //  newPacket.getRawPacket();
        //  std::cout<<      newPacket.toString()<<std::endl;
        struct timeval ts;
        ts.tv_usec = ipTuple.getTvUsec();
        ts.tv_sec = ipTuple.getTvSec();
        newPacket.getRawPacket()->setPacketTimeStamp(ts);

        std::cout<<"hier1"<<std::endl;



        //struct pcap_pkthdr pkthdr;
        //pkthdr.ts = ts;



        //pcpp::RawPacket raw = pcpp::RawPacket(x,newPacket.getRawPacket()->getRawDataLen(),ts, false, pcpp::LINKTYPE_IPV4);
        std::cout<<"hier2"<<std::endl;
        std::cout<<" linklayertype "<< newPacket.getRawPacket()->getLinkLayerType()<<std::endl;

        //newPacket.removeLayer(pcpp::Ethernet, 0);
        writer2.writePacket(*(newPacket.getRawPacket()));
        //writer2.writePacket(raw);
    }
    writer2.close();
*/
//////////////////////////////////////////////
  const unsigned char minTCPpacket[24] = { //min TCP packet truncate as soon as possible, after tcp ports
            //ip Header (20bytes)
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            //protocol flag (6 for tcp)
            0x06,
            //header checksum (unused)
            0x00, 0x00,
            //src IP address
            0x2f, 0x04, 0x5d, 0x57,
            //dst IP address
            0xed, 0x2a, 0x49, 0x68,

            //TCP Header (only first 4 bytes of 20+ bytes)
            //TCP src port
            0x01, 0xbb,
            //TCP dst port
            0x76, 0x70
    };
    const unsigned char minUDPpacket[24] = { //min UDP packet truncate as soon as possible, after udp ports
            //ip Header (20bytes)
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            //protocol flag (17 for UDP)
            0x11,
            //header checksum (unused)
            0x00, 0x00,
            //src IP address
            0x2f, 0x04, 0x5d, 0x57,
            //dst IP address
            0xed, 0x2a, 0x49, 0x68,

            //UDP Header (only first 4 bytes of 8 bytes) omitting length & checksum
            //UDP src port
            0x01, 0xbb,
            //UDP dst port
            0x76, 0x70
    };
    const unsigned char minICMPpacket[20] = { //min ICMP packet truncate as soon as possible, don't include icmp header since no information about icmp is captured
            //ip Header (20bytes)
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            //protocol flag (01 for ICMP)
            0x01,
            //header checksum (unused)
            0x00, 0x00,
            //src IP address
            0x2f, 0x04, 0x5d, 0x57,
            //dst IP address
            0xed, 0x2a, 0x49, 0x68,
    };



    pcap_t *handle = pcap_open_dead(DLT_RAW, 1 << 16); //second parameter is snapshot length, i think not relevant as set by caplen
    pcap_dumper_t *dumper = pcap_dump_open(handle, (filePath + "cap.pcap").c_str());


    {
        struct pcap_pkthdr pcap_hdr;
        pcap_hdr.caplen = sizeof(minTCPpacket); //captured length
        pcap_hdr.len = 28;            //actual length of packet (>=caplen) in bytes //for tcp must be >= 28 to prevent malformations
        pcap_hdr.ts.tv_sec = tuples.at(0).getTvSec();
        pcap_hdr.ts.tv_usec = tuples.at(0).getTvUsec();

        pcap_dump((u_char *) dumper, &pcap_hdr, minTCPpacket);
    }
    {
        struct pcap_pkthdr pcap_hdr;
        pcap_hdr.caplen = sizeof(minUDPpacket); //captured length
        pcap_hdr.len = 26;            //actual length of packet (>=caplen) in bytes //for udp must be >= 26 to prevent malformations
        pcap_hdr.ts.tv_sec = tuples.at(1).getTvSec();
        pcap_hdr.ts.tv_usec = tuples.at(1).getTvUsec();

        pcap_dump((u_char *) dumper, &pcap_hdr, minUDPpacket);
    }
    {
        struct pcap_pkthdr pcap_hdr;
        pcap_hdr.caplen = sizeof(minICMPpacket); //captured length
        pcap_hdr.len = 21;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
        pcap_hdr.ts.tv_sec = tuples.at(2).getTvSec();
        pcap_hdr.ts.tv_usec = tuples.at(2).getTvUsec();

        pcap_dump((u_char *) dumper, &pcap_hdr, minICMPpacket);
    }
    {
        unsigned char icmpPacket[20] = {0x00};
        makeIcmpPacket(tuples.at(0), icmpPacket);

        struct pcap_pkthdr pcap_hdr;
        pcap_hdr.caplen = sizeof(icmpPacket); //captured length
        pcap_hdr.len = 21;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
        pcap_hdr.ts.tv_sec = tuples.at(3).getTvSec();
        pcap_hdr.ts.tv_usec = tuples.at(3).getTvUsec();

        pcap_dump((u_char *) dumper, &pcap_hdr, icmpPacket);
    }
    pcap_dump_close(dumper);



    return 0;
}