#include <iostream>
#include <pcap/pcap.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/Layer.h>
#include <pcapplusplus/Packet.h>
#include <chrono>
//#include <PcapFileDevice.h>
int main() {
    std::cout << "\n\n\n\n\nHello, World!" << std::endl;

    /// Reading the file/ creating the reader

    auto start2 = std::chrono::high_resolution_clock::now();

    //pcpp::PcapFileReaderDevice reader("./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap");
    pcpp::PcapFileReaderDevice reader("./testfiles/example.pcap");

    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    std::cout<<"reading file duration: "<<duration2<<" nanoseconds\n";


    if (!reader.open())
    {
        printf("Error opening the pcap file\n");
        return 1;
    }


    ///parsing the file

    pcpp::RawPacketVector rpv;

    auto start3 = std::chrono::high_resolution_clock::now();

    reader.getNextPackets(rpv);

    auto end3 = std::chrono::high_resolution_clock::now();
    auto duration3 = std::chrono::duration_cast<std::chrono::nanoseconds>(end3-start3).count();
    std::cout<<"parsing duration: "<<duration3<<" nanoseconds\n";



    std::cout<<"packet count: "<<rpv.size()<<std::endl;

    long IPCounter = 0;
    long IPv4Counter = 0;
    long IPv6ounter = 0;

    for(pcpp::Packet p : rpv){
        if(p.isPacketOfType(pcpp::IP)){
            ++IPCounter;
        }
        if(p.isPacketOfType(pcpp::IPv4))
            ++IPv4Counter;
        if (p.isPacketOfType(pcpp::IPv6))
            ++IPv6ounter;
    }
    reader.close();

    std::cout<<"Parsing time per packet: "<<duration3/rpv.size();
    std::cout<<"\nIP Counter "<< IPCounter<<
             "\nIPv4 Counter "<<IPv4Counter<<
             "\nIPv6 Counter "<<IPv6ounter;


    ///reading single packets

    std::cout<<std::endl;

    //pcpp::Packet p = rpv.at(43);



    //for(pcpp::Packet p : rpv){
     for(int i = 0; i < 100; ++i){
         pcpp::Packet p = rpv.at(i);
        if(p.getFirstLayer()->getProtocol() == pcpp::Ethernet){
            p.removeFirstLayer();
            //printf("removing ethernet frame\n");
        }

              try {
                   pcpp::ProtocolType outer = p.getFirstLayer()->getProtocol();
                   p.removeFirstLayer();
                   pcpp::ProtocolType inner = p.getFirstLayer()->getProtocol();
                   if (outer != pcpp::IPv4) {
                       printf("outer is not IPV4: %li\n", outer);
                   }
                   if (inner != pcpp::TCP && inner != pcpp::UDP) {
                       printf("inner is not tcp or udp: %li\n\n", inner);
                   }
               }catch(...) {  }
               /* if(outer != pcpp::IPv4 || inner != pcpp::TCP|| inner != pcpp::UDP) //2 = ipv4, 8 = tcp, 10 = udp
                    std::cout<<"first protocol: "<<std::hex <<outer<<"\nsecond protocol: "<<std::hex <<inner<<"\n*****************************\n\n";
            */
    }


/*    pcpp::Packet p = rpv.at(17);

    std::cout<<"first protocol: "<<std::hex <<p.getFirstLayer()->getProtocol()<<std::endl;
    printf("%.2x\n", pcpp::DNS);
    pcpp::DNS;
    p.removeFirstLayer();
    std::cout<<"second protocol: "<<std::hex <<p.getFirstLayer()->getProtocol()<<std::endl;
    p.removeFirstLayer();




    if(p.isPacketOfType(pcpp::IPv4)){
        pcpp::IPv4Address srcIP = p.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
        pcpp::IPv4Address destIP = p.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();
        pcpp::ProtocolType protocolType = p.getLayerOfType<pcpp::IPv4Layer>()->getProtocol(); /// ipv4 protocol
        //if (protocolType == pcpp::ProtocolType.)
        if(p.isPacketOfType(pcpp::TCP)){
            std::cout<<"TCP"<<std::endl;
            protocolType= p.getLayerOfType<pcpp::TcpLayer>()->getProtocol();
        }

        // print source and dest IPs
        printf("Source IP is '%s'; Dest IP is '%s'; Protocol is %" PRIu64 "\n",
               srcIP.toString().c_str(),
               destIP.toString().c_str(),
               protocolType);

    }
*/


    return 0;
}
