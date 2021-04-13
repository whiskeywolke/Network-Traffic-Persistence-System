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

void readFromPcap_boostQueue(const std::string& fileName, boost::lockfree::queue<IPTuple>* queue){
//void readFromPcap_boostQueue(const std::string& fileName, threadedQueue<IPTuple>*queue ){
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
        std::cout << "Handling time per packet: " << duration2 / r.getConvertedPackets() << std::endl;
        std::cout << "converted: " << r.getConvertedPackets() << " parsed: " << r.getParsedPackets() << std::endl;
//    std::cout<<"vec size: "<<vec.size()<<std::endl;
//    std::cout<<"skipped: "<< r.getParsedPackets()-r.getConvertedPackets()<<std::endl;
//    std::cout<<"skipped: "<<r.getSkippedPackets();
//    convertedPackets = r.getConvertedPackets();
    }
}

void readFromPcap_ownQueue(const std::string& fileName, threadedQueue<IPTuple>*queue ){
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
        readingFinished2 = true;
        std::cout << "\nown queue:\n";
        std::cout << "total duration: " << duration2 << " nanoseconds\n";
        std::cout << "Handling time per packet: " << duration2 / r.getConvertedPackets() << std::endl;
        std::cout << "converted: " << r.getConvertedPackets() << " parsed: " << r.getParsedPackets() << std::endl;
//    std::cout<<"vec size: "<<vec.size()<<std::endl;
//    std::cout<<"skipped: "<< r.getParsedPackets()-r.getConvertedPackets()<<std::endl;
//    std::cout<<"skipped: "<<r.getSkippedPackets();
//    convertedPackets = r.getConvertedPackets();
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


int main() {

  /*  RingBuffer<IPTuple, 128>buffer{};
    IPTuple t = IPTuple();
    buffer.push(t);
*/
    boost::lockfree::queue<IPTuple> queue(100);
    threadedQueue<IPTuple> queue1{};

//    std::string inFilename = "./testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"; //6.7GB
//    std::string inFilename = "./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap"; //1.6GB
    std::string inFilename = "./testfiles/example.pcap";
//    std::string inFilename = "./testfiles/test3.pcap";
//    std::string inFilename = "./testfiles/test4.pcap";
//    std::string inFilename = "./testfiles/test5.pcap";
//    std::string inFilename = "./testfiles/test6.pcap";


    std::string outFileName1 = "testfiles/tuples1.bin";
    std::string outFileName2 = "testfiles/tuples2.bin";

    std::thread th2(readFromPcap_ownQueue, std::ref(inFilename), &queue1);
    std::thread th4(serializeToPcap_ownQueue, std::ref(outFileName2), &queue1);
    th2.join();
    th4.join();

    std::thread th1(readFromPcap_boostQueue, std::ref(inFilename), &queue);
    std::thread th3(serializeToPcap_boostQueue, std::ref(outFileName1), &queue);
    th1.join();
    th3.join();






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
