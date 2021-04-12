#include <iostream>
#include <pcap/pcap.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/Layer.h>
#include <pcapplusplus/Packet.h>
#include <chrono>
#include <fstream>
#include "IPTuple.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/lockfree/queue.hpp>

#include<omp.h>

//#include <PcapFileDevice.h>
int main() {
    std::cout << "\n\n\n\n\n"<< std::endl;

    IPTuple x = IPTuple();

    std::cout<<"size of tuple: "<< sizeof(x)<<std::endl;


    /// Reading the file/ creating the reader
    auto start2 = std::chrono::high_resolution_clock::now();
    //pcpp::PcapFileReaderDevice reader("./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap");
  //  pcpp::PcapFileReaderDevice reader("./testfiles/example.pcap");
    pcpp::PcapFileReaderDevice reader("./testfiles/test5.pcap");

    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    std::cout<<"reading file duration: "<<duration2<<" nanoseconds\n\n";
    if (!reader.open())
    {
        printf("Error opening the pcap file\n");
        return 1;
    }



    ///parsing the file
    pcpp::RawPacketVector rpv;
    auto start3 = std::chrono::high_resolution_clock::now();
    reader.getNextPackets(rpv);
    pcap_stat stat{};
    reader.getStatistics(stat);
    reader.close();
    auto end3 = std::chrono::high_resolution_clock::now();
    auto duration3 = std::chrono::duration_cast<std::chrono::nanoseconds>(end3-start3).count();

    if(stat.ps_recv!=rpv.size()){
        std::cout<<"packetcount does not match\n";
    }
    std::cout<<"packet count: "<<rpv.size()<<std::endl;
    std::cout<<"Parsing time per packet: "<<duration3/rpv.size()<<" \ttotaltime: "<< duration3<<std::endl;

    long unsigned IPCounter = 0;
    long unsigned IPv4Counter = 0;
    long unsigned IPv6ounter = 0;
    for(pcpp::Packet p : rpv){
        if(p.isPacketOfType(pcpp::IP)){
            ++IPCounter;
        }
        if(p.isPacketOfType(pcpp::IPv4))
            ++IPv4Counter;
        if (p.isPacketOfType(pcpp::IPv6))
            ++IPv6ounter;
    }
    if(IPCounter != IPv4Counter+IPv6ounter){
        std::cout<<"ip != ipv4+ipv6\n"<<
                    "\nIP Counter "<< IPCounter<<
                    "\nIPv4 Counter "<<IPv4Counter<<
                    "\nIPv6 Counter "<<IPv6ounter<<std::endl;
    }
    if(IPCounter!= rpv.size()){
        std::cout<<"some packets are not IP: ";
        std::cout<<"total packet count: "<<rpv.size()<<std::endl;

    }
    std::cout<<std::endl;



    ///reading single packets & converting to IPTUPLE format
    int skippedCount = 0;
    std::vector<IPTuple> tuples{};

    auto start4 = std::chrono::high_resolution_clock::now();
    for(size_t i = 0; i < rpv.size(); ++i){
         pcpp::Packet p = rpv.at(i);
        if(p.getFirstLayer()->getProtocol() == pcpp::Ethernet){
            p.removeFirstLayer();
            //printf("removing ethernet frame\n");
        }
     //   if(p.getFirstLayer()->getProtocol() != pcpp::IPv4 || p.getFirstLayer()->getProtocol() != pcpp::IPv4 ){ //if packet is not ipv4 or ipv6 then skip
  /*      if(!p.isPacketOfType(pcpp::IP)){
            printf("skipping packet %li\n", i);
            continue;
        }
  */
       if(p.isPacketOfType(pcpp::IPv4)){
                IPTuple t  = IPTuple(p.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress(),
                                     p.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress(),
                                     3,
                                    4);
                tuples.emplace_back(t);
            }
       else{
            ++skippedCount;
        }
    }
    auto end4 = std::chrono::high_resolution_clock::now();
    auto duration4 = std::chrono::duration_cast<std::chrono::nanoseconds>(end4-start4).count();
    std::cout<<"conversion time per packet: "<<duration4/rpv.size()<<" \ttotaltime: "<< duration4<<std::endl;
    if(skippedCount !=0)
        std::cout<<"tuples size: "<<tuples.size()<<", skipped packets: "<<skippedCount<<std::endl;
    std::cout<<std::endl;



    /// serialization with boost
    std::string filename = "testfiles/tuples.dump";
    int objectCount = tuples.size();
    auto start5 = std::chrono::high_resolution_clock::now();
    {
        std::ofstream ofs(filename);
        boost::archive::binary_oarchive oa(ofs);
        for(IPTuple t : tuples)
            oa << t;
    }
    auto end5 = std::chrono::high_resolution_clock::now();
    auto duration5 = std::chrono::duration_cast<std::chrono::nanoseconds>(end5-start5).count();
    std::cout << "writing time per packet: " << duration5 / objectCount << " \ttotaltime: "<< duration5<<std::endl<< std::endl;


    std::vector<IPTuple> readValues {};
    auto start6 = std::chrono::high_resolution_clock::now();
    {
        std::ifstream ifs(filename);
        boost::archive::binary_iarchive ia(ifs);
        IPTuple temp;
        for(int i = 0; i < objectCount; ++i) {
            ia >> temp;
            readValues.emplace_back(temp);
        }
    }
    auto end6 = std::chrono::high_resolution_clock::now();
    auto duration6 = std::chrono::duration_cast<std::chrono::nanoseconds>(end6-start6).count();
    std::cout << "reading time per packet: " << duration6 / objectCount << " \ttotaltime: "<< duration6<<std::endl<< std::endl;


    bool vectorsAreEqual;
    auto start7 = std::chrono::high_resolution_clock::now();
    vectorsAreEqual = std::equal(tuples.begin(), tuples.end(), readValues.begin());
    auto end7 = std::chrono::high_resolution_clock::now();
    auto duration7 = std::chrono::duration_cast<std::chrono::nanoseconds>(end7-start7).count();
    std::cout << "comparison time per packet: " << duration7 / objectCount <<" \ttotaltime: "<< duration7<<std::endl<< std::endl;

    if(!vectorsAreEqual){
        std::cout<<"vectors are not equal\n";
    }


////////////////////


/*
    int threadcount = 2;//omp_get_num_threads();
    int objcount = 10000000;
    auto start8 = std::chrono::high_resolution_clock::now();


#pragma omp parallel num_threads(threadcount)
{
    if((omp_get_thread_num()%omp_get_num_threads()) == 0)
    {
       // std::cout<<"threadnum 0: "<<omp_get_thread_num()<<std::endl;
        std::ofstream ofs("testfiles/filename0");
        boost::archive::binary_oarchive oa(ofs);
        for (int i = 0; i < objcount; ++i)
            oa << IPTuple();
    }
    if((omp_get_thread_num()+1)%omp_get_num_threads() == 0)
    {
      //  std::cout<<"threadnum 1: "<<omp_get_thread_num()<<std::endl;
        std::ofstream ofs("testfiles/filename1");
        boost::archive::binary_oarchive oa(ofs);
        for (int i = 0; i < objcount; ++i)
            oa << IPTuple();
    }
}
    auto end8 = std::chrono::high_resolution_clock::now();
    auto duration8 = std::chrono::duration_cast<std::chrono::nanoseconds>(end8-start8).count();
    std::cout << "write time per packet: " << duration8 / (objcount*threadcount) <<" \ttotaltime: "<< duration7<<std::endl<< std::endl;
*/
    return 0;
}
