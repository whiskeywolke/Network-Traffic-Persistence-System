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
#include "RingBuffer/threadedQueue.h"

//TODO remove global variable
u_long convertedPackets = 0;
bool readingFinished1 = false;
bool readingFinished2 = false;
std::mutex mutex;

void read_convertFromPcap_boostQueue(const std::string& fileName, boost::lockfree::queue<IPTuple>* queue){
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
        }
    } while (success);

    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    {
        std::lock_guard<std::mutex> lock(mutex);
        readingFinished1 = true;
        std::cout << "\nboost queue:\n";
        std::cout << "total duration: " << duration2 << " nanoseconds\n";
        std::cout << "Handling time per packet: " << duration2 / r.getParsedPackets() << std::endl;
        std::cout << "converted: " << r.getConvertedPackets() << " parsed: " << r.getParsedPackets() << std::endl;
//    std::cout<<"vec size: "<<vec.size()<<std::endl;
//    std::cout<<"skipped: "<< r.getParsedPackets()-r.getConvertedPackets()<<std::endl;
//    std::cout<<"skipped: "<<r.getSkippedPackets();
//    convertedPackets = r.getConvertedPackets();
    }
}

void read_convertFromPcap_threadQueue(const std::string& fileName, threadedQueue<IPTuple>*queue){
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
        }
    } while (success);

    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    {
        std::lock_guard<std::mutex> lock(mutex);
        readingFinished1 = true;
        std::cout << "\nthreaded queue:\n";
        std::cout << "total duration: " << duration2 << " nanoseconds\n";
        std::cout << "Handling time per packet: " << duration2 / r.getParsedPackets() << std::endl;
        std::cout << "converted: " << r.getConvertedPackets() << " parsed: " << r.getParsedPackets() << std::endl;
//    std::cout<<"vec size: "<<vec.size()<<std::endl;
//    std::cout<<"skipped: "<< r.getParsedPackets()-r.getConvertedPackets()<<std::endl;
//    std::cout<<"skipped: "<<r.getSkippedPackets();
//    convertedPackets = r.getConvertedPackets();
    }
}

void readFromPcap_ownQueue(const std::string& fileName, threadedQueue<pcpp::RawPacket>*queue ){
    Reader r = Reader(fileName.c_str());
    if(!r.open()){
        std::cout<<"could not open file!\n";
        return;
    }

    auto start2 = std::chrono::high_resolution_clock::now();

    pcpp::RawPacket raw;
    while(r.nextRawPacket(raw)){
        queue->push(raw);
    }


    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    {
        std::lock_guard<std::mutex> lock(mutex);
        readingFinished2 = true;
        std::cout << "\nown queue:\n";
        std::cout << "total duration: " << duration2 << " nanoseconds\n";
        std::cout << "Handling time per packet: " << duration2 / r.getParsedPackets() << std::endl;
        std::cout << "converted: " << r.getParsedPackets() << " parsed: " << r.getParsedPackets() << std::endl;
    }
}

void serializeToPcap_boostQueue(const std::string& fileName, boost::lockfree::queue<IPTuple>* queue){
//    auto start5 = std::chrono::high_resolution_clock::now();
    {
        std::ofstream ofs(fileName);
        boost::archive::binary_oarchive oa(ofs);
        IPTuple temp;

        u_long counter = 0;
        while(true) {
            if(queue->pop(temp)) {  //only save if queue is not empty
                ++counter;
                oa << temp;
            }
            if(readingFinished1 && counter>=convertedPackets)
                break;
        }
    }
//    auto end5 = std::chrono::high_resolution_clock::now();
//    auto duration5 = std::chrono::duration_cast<std::chrono::nanoseconds>(end5-start5).count();
//    std::cout << "writing time per packet: " << duration5 / convertedPackets << " \ttotaltime: "<< duration5<<std::endl<< std::endl;
}

void serializeToPcap_ownQueue(const std::string& fileName, threadedQueue<IPTuple>*queue){
//    auto start5 = std::chrono::high_resolution_clock::now();
    {
        std::ofstream ofs(fileName);
        boost::archive::binary_oarchive oa(ofs);
        u_long counter = 0;
        while(true) {
            IPTuple temp;
            queue->wait_and_pop(temp);
            oa << temp;
            ++counter;

            if(counter >4631)
                std::cout<<"counter: "<<counter<<"\n";
            if(readingFinished2 && counter>=convertedPackets)
                return;
        }
    }
//    auto end5 = std::chrono::high_resolution_clock::now();
//    auto duration5 = std::chrono::duration_cast<std::chrono::nanoseconds>(end5-start5).count();
//    std::cout << "writing time per packet: " << duration5 / convertedPackets << " \ttotaltime: "<< duration5<<std::endl<< std::endl;
}

/*
void readRawFromPcap(const std::string& fileName, boost::lockfree::queue<DataContainer>* queue){
    Reader r = Reader(fileName.c_str());
    if(!r.open()){
        std::cout<<"could not open file!\n";
        return;
    }

    auto start2 = std::chrono::high_resolution_clock::now();
    DataContainer temp;
    while(r.nextPacketData(temp)){
        queue->push(temp);
    }
    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    {
        std::lock_guard<std::mutex> lock(mutex);
        readingFinished1 = true;
        std::cout << "\nDataContainer:\n";
        std::cout << "total duration: " << duration2 << " nanoseconds\n";
        std::cout << "Handling time per packet: " << duration2 / r.getParsedPackets() << std::endl;
        std::cout << "parsed: " << r.getConvertedPackets() << " parsed: " << r.getParsedPackets() << std::endl;
//    std::cout<<"vec size: "<<vec.size()<<std::endl;
//    std::cout<<"skipped: "<< r.getParsedPackets()-r.getConvertedPackets()<<std::endl;
//    std::cout<<"skipped: "<<r.getSkippedPackets();
        convertedPackets = r.getParsedPackets();
        readingFinished1 = true;
    }
}
*/

void readRawFromPcap(const std::string& fileName, threadedQueue<DataContainer>* queue){
    Reader r = Reader(fileName.c_str());
    if(!r.open()){
        std::cout<<"could not open file!\n";
        return;
    }

    auto start2 = std::chrono::high_resolution_clock::now();
    DataContainer temp;
    while(r.nextPacketData(temp)){
        queue->push(temp);
    }
    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    {
        std::lock_guard<std::mutex> lock(mutex);
        readingFinished1 = true;
        std::cout << "\nDataContainer:\n";
        std::cout << "total duration: " << duration2 << " nanoseconds\n";
        std::cout << "Handling time per packet: " << duration2 / r.getParsedPackets() << std::endl;
        std::cout << "parsed: " << r.getConvertedPackets() << " parsed: " << r.getParsedPackets() << std::endl;
//    std::cout<<"vec size: "<<vec.size()<<std::endl;
//    std::cout<<"skipped: "<< r.getParsedPackets()-r.getConvertedPackets()<<std::endl;
//    std::cout<<"skipped: "<<r.getSkippedPackets();
        convertedPackets = r.getParsedPackets();
        readingFinished1 = true;
    }
}

void pcppReader(const std::string& fileName, threadedQueue<pcpp::RawPacket>* queue){
    pcpp::PcapFileReaderDevice r("./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap");
    if(!r.open()){
        std::cout<<"could not open file!\n";
        return;
    }


    auto start2 = std::chrono::high_resolution_clock::now();
    pcpp::RawPacket temp;
    while(r.getNextPacket(temp)){
        queue->push(temp);
    }
    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    {
        std::lock_guard<std::mutex> lock(mutex);
        readingFinished1 = true;
        std::cout << "\nDataContainer:\n";
        std::cout << "total duration: " << duration2 << " nanoseconds\n";
        pcap_stat stat{};
        r.getStatistics(stat);
        auto packetcount = stat.ps_recv;
        std::cout << "Handling time per packet: " << duration2 / packetcount << std::endl;
        std::cout << "parsed: " << packetcount<< " parsed: " << packetcount << std::endl;
//    std::cout<<"vec size: "<<vec.size()<<std::endl;
//    std::cout<<"skipped: "<< r.getParsedPackets()-r.getConvertedPackets()<<std::endl;
//    std::cout<<"skipped: "<<r.getSkippedPackets();
        convertedPackets = packetcount;
        readingFinished1 = true;
    }
}

void pcppReader(const std::string& fileName, pcpp::RawPacketVector *rpv){
    pcpp::PcapFileReaderDevice r("./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap");
    if(!r.open()){
        std::cout<<"could not open file!\n";
        return;
    }


    auto start2 = std::chrono::high_resolution_clock::now();

    r.getNextPackets(*rpv);
    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2-start2).count();
    {
        std::lock_guard<std::mutex> lock(mutex);
        readingFinished1 = true;
        std::cout << "\nDataContainer:\n";
        std::cout << "total duration: " << duration2 << " nanoseconds\n";
        pcap_stat stat{};
        r.getStatistics(stat);
        auto packetcount = stat.ps_recv;
        std::cout << "Handling time per packet: " << duration2 / packetcount << std::endl;
        std::cout << "parsed: " << packetcount<< " parsed: " << packetcount << std::endl;
//    std::cout<<"vec size: "<<vec.size()<<std::endl;
//    std::cout<<"skipped: "<< r.getParsedPackets()-r.getConvertedPackets()<<std::endl;
//    std::cout<<"skipped: "<<r.getSkippedPackets();
        convertedPackets = packetcount;
        readingFinished1 = true;
    }
}


int main() {

///boost queue does not free memory after its lifecycle ended, no problem since the program will have a fixed number of queues during its runtime
///but it is hard to check for memory leaks

//    std::string inFilename = "./testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"; //6.7GB      (107555567 packets) (no payload)
    std::string inFilename = "./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap"; //1.6GB      (27013768 packets)  (no payload)
//    std::string inFilename = "./testfiles/example.pcap";
//    std::string inFilename = "./testfiles/test3.pcap";
//    std::string inFilename = "./testfiles/test4.pcap";
//    std::string inFilename = "./testfiles/test5.pcap"; //(3 packets)
//    std::string inFilename = "./testfiles/test6.pcap";  // (1031565 packets) with payload

/*
    std::string outFileName1 = "testfiles/tuples1.bin";
    std::string outFileName2 = "testfiles/tuples2.bin";

    std::thread th2(readFromPcap_ownQueue, std::ref(inFilename), &queue1);
    std::thread th4(serializeToPcap_ownQueue, std::ref(outFileName2), &queue1);
    th2.join();
    th4.join();

    std::thread th1(read_convertFromPcap_threadQueue, std::ref(inFilename), &queue);
    std::thread th3(serializeToPcap_boostQueue, std::ref(outFileName1), &queue);
    th1.join();
    th3.join();
*/
    char x;
    std::cout<<"start\n";
/*
    {
       threadedQueue<IPTuple> queue{};
        uint64_t i = 0;
        for(; i < 107555567; ++i){
            IPTuple pointer = IPTuple();
            queue.push(pointer);
        }

        int counter = 0;
        IPTuple temp;
        while (!queue.empty()){
            queue.try_pop(temp);
            ++counter;
        }
        std::cout<<"counter: "<<counter<<std::endl;
        std::cout<<i<<" char to continue queue: ";
        char c;
        std::cin>>c;
        std::cout<<"emptying: "<<std::endl;
    }
    std::cout<<"myqueue is deleted memory should be freed: ";
    std::cin>>x;
    std::cout<<"\ncontinuing: "<<std::endl;
*/

/*
    {
        ///test when dataContainer memory is freed
        threadedQueue<DataContainer> queue{};
        readRawFromPcap(inFilename, &queue);

        std::cout<<"insert char to empty queue: ";
        std::cin>>x;
        while (!queue.empty()){
            DataContainer temp;
            queue.try_pop(temp);
            //temp.clear();
        }

        std::cout<<"insert char to delete queue: ";
        std::cin>>x;


    }
    std::cout<<"myqueue is deleted memory should be freed";
    std::cin>>x;
    std::cout<<"continuing: "<<std::endl;
*/

/*    {
        boost::lockfree::queue<IPTuple> queue(1000000);
        uint64_t i = 0;
        for(; i < 107555567; ++i){
            IPTuple pointer = IPTuple();
            queue.push(pointer);
        }

        std::cout<<i<<" char to continue queue: ";
        char c;
        std::cin>>c;
        std::cout<<"emptying: "<<std::endl;

        int counter = 0;
        IPTuple temp;
        while (!queue.empty()){
            queue.pop(temp);
            ++counter;
        }
        std::cout<<"counter: "<<counter<<std::endl;
    }
    std::cout<<"queue is deleted memory should be freed";
    std::cin>>x;
    std::cout<<"continuing: "<<std::endl;
*/

/*
    const uint8_t *pointer;
    {


        threadedQueue<pcpp::RawPacket> queue{};
        //pcppReader(inFilename, &queue);
        //readFromPcap_ownQueue(inFilename, &queue);

        std::cout<<"insert char to empty queue: ";
        std::cin>>x;
        bool first = true;
        while (!queue.empty()){
            pcpp::RawPacket temp;
            queue.try_pop(temp);

            if(first){
                pointer = temp.getRawData();
                std::cout<<"pointer: " << pointer<<std::endl;
                first = false;
            }

            temp.clear();
        }
        //std::cout<<"insert char to delete queue: ";
        //std::cin>>x;
    }
   // delete pointer;
    std::cout<<"pointer: " << pointer<<std::endl;
    std::cout<<"myqueue is deleted memory should be freed: ";
    std::cin>>x;
    std::cout<<"continuing: "<<std::endl;

*/

    const uint8_t *pointer2;
    {

        pcpp::RawPacketVector rpv{};

        pcppReader(inFilename, &rpv);

 /*       std::cout<<"insert char to empty queue: ";
        std::cin>>x;
        bool first = true;
        while (!rpv.empty()){
            pcpp::RawPacket temp;
            queue.try_pop(temp);

            if(first){
                pointer2 = temp.getRawData();
                std::cout<<"pointer: " << pointer2<<std::endl;
                first = false;
            }

            temp.clear();
        }
  */      std::cout<<"insert char to delete queue: ";
        std::cin>>x;
    }
    // delete pointer;
    std::cout<<"pointer: " << pointer2<<std::endl;
    std::cout<<"myqueue is deleted memory should be freed: ";
    std::cin>>x;
    std::cout<<"continuing: "<<std::endl;




    ///deserialize
/*

    std::vector<IPTuple> readValues {};
    auto start6 = std::chrono::high_resolution_clock::now();
    {
        std::ifstream ifs(outFileName1);
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
*/
    std::cout << "\ncapture finished" << std::endl;
    return 0;
}
