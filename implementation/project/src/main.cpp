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
#include <fstream>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/Device.h>
#include "IpTuple/IPTuple.h"
#include <pcapplusplus/IpUtils.h>
#include <pcapplusplus/IPv4Layer.h>

using namespace std;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main() {
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // open capture file for offline processing
    descr = pcap_open_offline("./testfiles/example.pcap", errbuf);
    if (descr == NULL) {
        cout << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

    pcap_pkthdr pkthdr;
    const uint8_t* packetData =  pcap_next(descr,&pkthdr);
    if (packetData == NULL)
    {
        std::cout<<"Packet could not be read. Probably end-of-file\n";
        return 1;
    }
    uint8_t* pMyPacketData = new uint8_t[pkthdr.caplen];
    memcpy(pMyPacketData, packetData, pkthdr.caplen);

    pcpp::RawPacket rawPacket;
    int linkLayer = pcap_datalink(descr);
    if(!pcpp::RawPacket::isLinkTypeValid(linkLayer)){
        std::cout<<"linklayer is not valid\n";
        return 1;
    }

    pcpp::LinkLayerType m_PcapLinkLayerType = static_cast<pcpp::LinkLayerType>(linkLayer);
    bool success = rawPacket.setRawData(pMyPacketData, pkthdr.caplen, pkthdr.ts,static_cast<pcpp::LinkLayerType>(m_PcapLinkLayerType), pkthdr.len);
    if(!success){
        std::cout<<"could not set raw packet\n";
        return 1;
    }

    pcpp::Packet p = &rawPacket;

    if(p.getFirstLayer()->getProtocol() == pcpp::Ethernet){
        p.removeFirstLayer();
        printf("removing ethernet frame\n");
    }
    if(p.isPacketOfType(pcpp::IPv4)){
        IPTuple t  = IPTuple(p.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                             p.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                             3,
                             4);
        std::cout<<t.toString()<<std::endl;
        auto dst = pcpp::IPv4Address(t.getV4Dst());
        auto src = pcpp::IPv4Address(t.getV4Src());

        std::cout<<"dst: "<<dst.toString()<<" src: "<<src.toString()<<std::endl;
    }

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
    cout << "capture finished" << endl;

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
    string dataStr = "";

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
            cout << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << endl;
            if (dataLength > 0) {
                cout << dataStr << endl;
            }
        }
    }
}
