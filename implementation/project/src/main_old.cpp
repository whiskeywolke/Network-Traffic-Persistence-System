#include <iostream>
#include <pcap/pcap.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/Layer.h>
#include <pcapplusplus/Packet.h>
#include <chrono>
#include <fstream>
#include "IpTuple/IPTuple.h"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/lockfree/queue.hpp>
#include <boost/thread/thread.hpp>
#include <pcap/pcap.h>
//#include "reader/Reader.h"


#include<omp.h>
#include "RingBuffer/RingBuffer.h"
//#include <PcapFileDevice.h>

#define QUEUESIZE  128
#define BATCHSIZE 100


void reserveSpace(){

}
class Wrapper{
public:
    pcpp::RawPacket p;

    Wrapper(const pcpp::RawPacket & x): p(x){};
};

int main() {

    std::cout << "\n\n\n\n\n"<< std::endl;

    boost::lockfree::queue<pcpp::RawPacketVector*> queue(128);
    const char *fileName = "./testfiles/example.pcap";

    {
        pcpp::PcapFileReaderDevice r(fileName);
        r.open();
        pcpp::RawPacketVector rpv;
        r.getNextPackets(rpv);
        queue.push(&rpv);
    }

    pcpp::RawPacketVector *rpv2;
    pcpp::RawPacket testp;
    queue.pop(rpv2);
    pcpp::Packet p =  rpv2->at(0);

    p.getFirstLayer();

    pcap_loop()


//    RingBuffer<pcpp::RawPacketVector, 10> r{};

    pcap* pcap;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr* hdr                      = {};
    const u_char*       pl_buf                   = {};
    int                 pcap_status              = 0;
    bool                done                     = false;


    {
        if (!(pcap = pcap_open_offline(fileName, errbuf)))
            throw std::runtime_error("pcap_reader: could not open ");
    }
    {
        pcap_status = pcap_next_ex(pcap, &hdr, &pl_buf);

        if (pcap_status == -2)
            done = true;
    }

    const unsigned char** buf_;
    unsigned long& timestamp_us;
    unsigned& frame_len_;
    unsigned& cap_len_;

    {
        *buf_ = pl_buf;
        timestamp_us_ = (unsigned long) _hdr->ts.tv_sec * 1000000 + _hdr->ts.tv_usec;
        frame_len_ = _hdr->len;
        cap_len_   = _hdr->caplen;
        return !_done;
    }



/*

    //pcpp::PcapFileReaderDevice reader("./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap");
    pcpp::PcapFileReaderDevice reader("./testfiles/example.pcap");

    if (!reader.open()){
        throw "error opening the pcap file";
    }




    ///parsing the file
    pcpp::RawPacketVector rpv;

    reader.getNextPackets(rpv);
    pcap_stat stat{};
    reader.getStatistics(stat);
    reader.close();


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


/*
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
 */
  /*      if(!p.isPacketOfType(pcpp::IP)){
            printf("skipping packet %li\n", i);
            continue;
        }
  */
   /*    if(p.isPacketOfType(pcpp::IPv4)){
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

//////// test boost lockfree queue

    boost::lockfree::queue<int> queue(128);
    queue.push(1);
    int ret;
    queue.pop(ret);
    std::cout<<"ret: "<<ret<<std::endl;

////////////////////

*/
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
    std::cout<<"fin"<<std::endl;
    return 0;
}
