#include "stdlib.h"
//#include <pcapplusplus/PcapLiveDeviceList.h>
//#include <pcapplusplus/PlatformSpecificUtils.h>
#include <pcapplusplus/PcapFileDevice.h>
//#include <pcapplusplus/RawPacket.h>
#include <iostream>
#include "RingBuffer/ThreadedQueue.h"
#include "Reader/Reader.h"
#include "Converter/Converter.h"
#include "Model/Aggregate.h"
#include "Model/CompressedBucket.h"

#include <memory>
#include <thread>

#include <boost/lockfree/queue.hpp>
#include <fstream>

bool readingFinished = false;
int parsedPackets = 0;
std::atomic<int> processedPackets { 0};

std::string getPredefinedFilterAsString(){
    pcpp::ProtoFilter tcpProtocolFilter(pcpp::TCP);
    pcpp::ProtoFilter udpProtocolFilter(pcpp::UDP);
    pcpp::ProtoFilter icmpProtocolFilter(pcpp::ICMP);
    pcpp::ProtoFilter ipv4ProtocolFilter(pcpp::IPv4);

    pcpp::OrFilter orFilter;
    orFilter.addFilter(&tcpProtocolFilter);
    orFilter.addFilter(&udpProtocolFilter);
    orFilter.addFilter(&icmpProtocolFilter);

    pcpp::AndFilter andFilter;
    andFilter.addFilter(&ipv4ProtocolFilter);
    andFilter.addFilter(&orFilter);

    std::string res{};
    andFilter.parseToString(res);
    return res;
}


void readPcapFile(const std::string& fileName, boost::lockfree::queue<RawContainer*>* queue){
    Reader dev(fileName.c_str());
    if (!dev.open())
    {
        printf("Cannot open device\n");
        exit(1);
    }
    dev.setFilter(getPredefinedFilterAsString());
    RawContainer* temp;

    auto start = std::chrono::high_resolution_clock::now();

    while(dev.next(temp)){
        queue->push(temp);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
    std::cout << "reading duration: " << duration << " nanoseconds\n";
    std::cout << "Handling time per packet: " << duration / dev.getParsedPackets() << "; Packets per second: "<<1000000000/(duration / dev.getParsedPackets() ) <<std::endl;
    std::cout << "Packet Count: " << dev.getParsedPackets() << std::endl;
    parsedPackets = dev.getParsedPackets();
    readingFinished = true;
}

void convert(boost::lockfree::queue<RawContainer*>* queue1, boost::lockfree::queue<IPTuple>* queue2){
    RawContainer* input = nullptr;

    auto start = std::chrono::high_resolution_clock::now();


    while(!readingFinished || processedPackets<parsedPackets){
        IPTuple ipTuple;
        if(queue1->pop(input)) {
            if (Converter::convert(input, ipTuple)) {
                //std::cout << ipTuple.toString() << std::endl;
                //std::cout<<"timestamp "<<input->timestamp.tv_sec<<" "<< input->timestamp.tv_usec <<std::endl;

                queue2->push(ipTuple);
            }

            // free memory allocated while reading
            delete[] input->buf;
            delete input;
            ++processedPackets;
        }
        input = nullptr;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count();
    std::cout << "conversion duration: " << duration << " nanoseconds\n";

}

void aggregate(boost::lockfree::queue<IPTuple>* queue1, boost::lockfree::queue<SortedPackets*>* queue2){
    Aggregate& b = Aggregate::getInstance();


    auto start = std::chrono::high_resolution_clock::now();
    auto time_since_flush = std::chrono::high_resolution_clock::now();
    //while(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count() <= 10 ){
    while(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count() <= 10 || !queue1->empty()){  //TODO checking if empty only makes sense with single thread
        IPTuple t;
        if(queue1->pop(t)){
            b.add(t);
        }
        auto current_time = std::chrono::high_resolution_clock::now();
        if(std::chrono::duration_cast<std::chrono::seconds>(current_time - time_since_flush).count() >= 2 ){
            b.flush(queue2);
            time_since_flush = current_time;
            //std::cout<<"flushing"<<std::endl;
        }
    }
    b.flush(queue2);

}


int main(int argc, char* argv[]) {
//    std::string inFilename = "./testfiles/equinix-nyc.dirB.20180517-134900.UTC.anon.pcap"; //6.7GB      (107555567 packets) (no payload)
//    std::string inFilename = "./testfiles/equinix-nyc.dirA.20180517-125910.UTC.anon.pcap"; //1.6GB      (27013768 packets)  (no payload)
//    std::string inFilename = "./testfiles/example.pcap";
//    std::string inFilename = "./testfiles/test3.pcap";
    std::string inFilename = "./testfiles/test4.pcap";
//    std::string inFilename = "./testfiles/test5.pcap"; //(3 packets)
//    std::string inFilename = "./testfiles/test6.pcap";  // (1031565 packets) with payload


    boost::lockfree::queue<RawContainer *> queueRaw{10000000};
    boost::lockfree::queue<IPTuple> queueParsed{10000000};
    boost::lockfree::queue<SortedPackets *> queueSorted{50000};
    boost::lockfree::queue<CompressedBucket *> queueCompressed{50000};


    auto start = std::chrono::high_resolution_clock::now();

    std::thread th1(readPcapFile, std::ref(inFilename), &queueRaw);


    std::thread th2(convert, &queueRaw,
                    &queueParsed); //more than one converter thread reduces performance (synchronization overhead), probably system dependant
    std::thread th3(aggregate, &queueParsed, &queueSorted);

    th1.join();
    th2.join();
    th3.join();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    std::cout << "total duration: " << duration << " nanoseconds\n";


    std::vector<std::vector<IPTuple>> comparisonVector{};
    //TODO create compressedObjects

    int bucketCount = 0;
    int sum = 0;
    size_t largestBucket = 0;
    while (!queueSorted.empty()) {
        SortedPackets *sp;
        if (queueSorted.pop(sp)) {
            //std::cout<<"elements in Aggregate: "<<sp->length<<std::endl;
            sum += sp->length;
            if (sp->length > largestBucket) {
                largestBucket = sp->length;
            }
            CompressedBucket *bucket = new CompressedBucket{};
            std::vector<IPTuple> temp{};
            for (size_t i = 0; i < sp->length; ++i) {
                bucket->add(sp->start[i]);
                temp.push_back(sp->start[i]);
            }
            queueCompressed.push(bucket);
            comparisonVector.push_back(temp);
            //cleanup

            delete[] sp->start;
            delete sp;
            ++bucketCount;
        }
    }
    std::cout << "average packets per bucket: " << sum / bucketCount << std::endl;
    std::cout << "largest bucket: " << largestBucket << std::endl;





    //TODO write group of compressedObjects (5000) to single file timestamp as name
    //TODO save raw IPTuple for comparison
    std::cout << "writing" << std::endl;

    std::string outFileName = "./testfiles/out.bin";
    int counter = 0;
    {
        std::ofstream ofs(outFileName);
        boost::archive::binary_oarchive oa(ofs);
        CompressedBucket *b;
        while (queueCompressed.pop(b)) {
            oa << *b;
            ++counter;
        }
    }


    //TODO read from file
    std::vector<CompressedBucket> readData{};
    {
        std::ifstream ifs(outFileName);
        boost::archive::binary_iarchive ia(ifs);
        CompressedBucket temp;
        for (int i = 0; i < counter; ++i) {
            ia >> temp;
            readData.emplace_back(temp);
        }
    }


    //TODO decompress
    std::vector<std::vector<IPTuple>> decompressedTuples{};

    for (CompressedBucket b: readData) {
        std::vector<IPTuple> temp{};
        b.getData(temp);
        decompressedTuples.push_back(temp);
    }



    //TODO compare with @comparisonVector if decompression works

//    std::cout<<comparisonVector.at(0).at(0).toString()<<std::endl;
//    std::cout<<decompressedTuples.at(0).at(0).toString()<<std::endl;

//    std::cout<<"elements are equal: "<< (comparisonVector.at(0).at(0) == decompressedTuples.at(0).at(0))<<std::endl;


    bool vectorsAreEqual = std::equal(comparisonVector.at(0).begin(), comparisonVector.at(0).end(),
                                      decompressedTuples.at(0).begin());
    std::cout << "comparison bucket count: " << comparisonVector.size() << " decompressed bucket count: " << decompressedTuples.size() << std::endl;
    std::cout << "vectors are equal: " << vectorsAreEqual << std::endl;

    for (size_t i = 0; i < comparisonVector.size(); ++i) {
        for (size_t j = 0; j < comparisonVector.at(i).size(); ++j) {
            if(!(comparisonVector.at(i).at(j) == decompressedTuples.at(i).at(j))){
                std::cout << i << j << std::endl;
                std::cout << "comparison  : " << comparisonVector.at(i).at(j).toString() << std::endl;
                std::cout << "decompressed: " << decompressedTuples.at(i).at(j).toString() << std::endl;
            }
        }
    }






    // for comparison of compression
 /*   {
        std::string outFileNameComp = "./testfiles/uncompressedOut.bin";
        std::ofstream ofs(outFileNameComp);
        boost::archive::binary_oarchive oa(ofs);
        for (IPTuple t : comparisonVector) {
            oa << t;
        }
    }
*/


    // print results
    std::cout << "queueRaw empty: "         << queueRaw.empty() << std::endl;
    std::cout << "queueParsed empty: "      << queueParsed.empty() << std::endl;
    std::cout << "queueSorted empty: "      << queueSorted.empty() << std::endl;
    std::cout << "queueCompressed empty: "  << queueCompressed.empty() << std::endl;

}