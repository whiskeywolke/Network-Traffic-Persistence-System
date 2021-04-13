#include <iostream>
#include <vector>

#include <chrono>
#include <fstream>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/lockfree/queue.hpp>

#include <thread>
#include "IpTuple/IPTuple.h"
#include "reader/Reader.h"
#include "RingBuffer/RingBuffer.h"

int convertedPackets = 0;

void readFromPcap(const std::string& fileName, boost::lockfree::queue<IPTuple>* queue){
//void readFromPcap(const std::string& fileName, RingBuffer<IPTuple, 128>*queue ){
    Reader r = Reader(fileName.c_str());
    if(!r.open()){
        std::cout<<"could not open file!\n";
        return;
    }
    bool success;
    auto start2 = std::chrono::high_resolution_clock::now();
    IPTuple tempTuple;
    do{
        success = r.nextIpTuple(tempTuple);
        if(success) {
            queue->push(tempTuple);
           // queue->push(IPTuple());
        }
    } while (success);

    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    std::cout<<"total duration: "<<duration2<<" nanoseconds\n\n";
    std::cout<<"Handling time per packet: "<<duration2/r.getConvertedPackets()<< std::endl;
    std::cout<<"converted: "<<r.getConvertedPackets() << " parsed: " << r.getParsedPackets()<<std::endl;
//    std::cout<<"vec size: "<<vec.size()<<std::endl;
//    std::cout<<"skipped: "<< r.getParsedPackets()-r.getConvertedPackets()<<std::endl;
//    std::cout<<"skipped: "<<r.getSkippedPackets();
    convertedPackets = r.getConvertedPackets();
}

void writeToPcap(const std::string& fileName, boost::lockfree::queue<IPTuple>* queue){
//void writeToPcap(const std::string& fileName, RingBuffer<IPTuple, 128>*queue ){
    auto start5 = std::chrono::high_resolution_clock::now();
    {
        std::ofstream ofs(fileName);
        boost::archive::binary_oarchive oa(ofs);
        while(!queue->empty()) { //TODO empty not optimal
            IPTuple temp;
            queue->pop(temp);
            //temp = queue->pop();
            oa << temp;
        }
    }
    auto end5 = std::chrono::high_resolution_clock::now();
    auto duration5 = std::chrono::duration_cast<std::chrono::nanoseconds>(end5-start5).count();
    std::cout << "writing time per packet: " << duration5 / convertedPackets << " \ttotaltime: "<< duration5<<std::endl<< std::endl;
}

int main() {

  /*  RingBuffer<IPTuple, 128>buffer{};
    IPTuple t = IPTuple();
    buffer.push(t);
*/
    boost::lockfree::queue<IPTuple> queue(46310);

//    std::string inFilename = "./testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"; //6.7GB
//    std::string inFilename = "./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap"; //1.6GB
    std::string inFilename = "./testfiles/example.pcap";
//    std::string inFilename = "./testfiles/test3.pcap";
//    std::string inFilename = "./testfiles/test4.pcap";
//    std::string inFilename = "./testfiles/test5.pcap";
//    std::string inFilename = "./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap";

    std::string outFileName = "testfiles/tuples.dump";

//    std::thread th1(readFromPcap, std::ref(inFilename), &queue);
//    std::thread th2(writeToPcap, std::ref(outFileName), &queue);

    readFromPcap(inFilename, &queue);
    writeToPcap(outFileName, &queue);

//    th1.join();
//    th2.join();

    std::cout << "capture finished" << std::endl;

    return 0;
}
