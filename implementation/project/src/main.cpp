#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/IcmpLayer.h>
#include "IpTuple/IPTuple.h"
#include <pcapplusplus/IpUtils.h>
#include <pcapplusplus/IPv4Layer.h>
#include <boost/lockfree/queue.hpp>
#include "stdlib.h"
#include "pcapplusplus/SystemUtils.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/HttpLayer.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "IpTuple/IPTuple.h"
#include "reader/Reader.h"


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main() {


    boost::lockfree::queue<IPTuple> queue(26597500);
    std::vector<IPTuple> vec{};

 //   std::string filename = "./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap";
    //   std::string filename = "./testfiles/example.pcap";
  //  std::string filename = "./testfiles/test3.pcap";
 //   std::string filename = "./testfiles/test4.pcap";
    std::string filename = "./testfiles/test5.pcap";
 //   std::string filename = "./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap";

    pcpp::PcapFileReaderDevice reader(filename.c_str());
    reader.open();
    std::vector<pcpp::RawPacket>testvec{};



    Reader r = Reader(filename.c_str());
    if(!r.open()){
        std::cout<<"could not open file!\n";
        return 1;
    }

  /*  for(int i = 0; i < 17; ++i){
        pcpp::RawPacket p1, p2;
        reader.getNextPacket(p1);
        std::cout<<"eins"<<std::endl;
        r.nextRawPacket(p2);
        std::cout<<"zwei"<<std::endl;

        testvec.emplace_back(p1);
        testvec.emplace_back(p2);

    }
*/

 /*   bool success;
    do{
        IPTuple test;
        success = r.nextIpTuple(test);
        vec.emplace_back(test);
  //      queue.push(test);
    } while (success);
*/

    std::cout<<"converted: "<<r.getConvertedPackets() << " parsed: " << r.getParsedPackets()<<std::endl;

    IPTuple t2;
    for(int i = 0; i < 81;++i){
        t2 = IPTuple();
        std::cout<<i+1<<std::endl;
        r.nextIpTuple(t2);
     //   vec.emplace_back(t2);
     //   queue.push(t2);
    }
    std::cout<<"converted: "<<r.getConvertedPackets() << " parsed: " << r.getParsedPackets()<<std::endl;
    r.nextIpTuple(t2);
    std::cout<<"converted: "<<r.getConvertedPackets() << " parsed: " << r.getParsedPackets()<<std::endl;


    /////////////////
/*
    // Open the dump file
    pcap_dumper_t *dumpfile = pcap_dump_open(descr, "argv[1]");

    if(dumpfile==NULL)
    {
        fprintf(stderr,"\nError opening output file\n");
        return -1;
    }
*/

    // start packet processing loop, just like live capture
    /*(unsigned char *)dumpfile*/
    /*
    if (pcap_loop(descr,0, packetHandler,  NULL) < 0) {
        cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }
*/
    std::cout << "capture finished" << std::endl;

    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    std::string dataStr = "";

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);
            data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

            // convert non-printable characters, other than carriage return, line feed,
            // or tab into periods when displayed.
            for (int i = 0; i < dataLength; i++) {
                if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
                    dataStr += (char)data[i];
                } else {
                    dataStr += ".";
                }
            }

            // print the results
            std::cout << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << std::endl;
            if (dataLength > 0) {
                std::cout << dataStr << std::endl;
            }
        }
    }
}
