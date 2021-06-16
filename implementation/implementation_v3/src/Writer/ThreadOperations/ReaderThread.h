//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_READERTHREAD_H
#define IMPLEMENTATION_READERTHREAD_H

#include "../../Common/ConcurrentQueue/concurrentqueue.h"
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapFilter.h>

namespace writer {
    namespace threadOperations {
        std::string getPredefinedFilterAsString() {
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

        void readPcapFile(const std::string &fileName, std::vector<bool> *status, int threadID,
                          moodycamel::ConcurrentQueue <pcpp::RawPacket> *outQueue, std::mutex &status_mutex,
                          std::atomic<bool> &readingFinished, std::atomic<long> &readingDuration,
                          std::atomic<long> &readPackets) {
            pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(fileName.c_str());

            if (reader == nullptr || !reader->open()) {
                printf("Error creating reader device\n");
                exit(1);
            }
            reader->setFilter(getPredefinedFilterAsString());
            auto start = std::chrono::high_resolution_clock::now();

            pcpp::RawPacket temp;
            while (reader->getNextPacket(temp)) {
                outQueue->enqueue(temp);
            }
///wip
/*
    while(true){
        pcpp::RawPacketVector segment{};
        size_t count = reader->getNextPackets(segment, 1000);
        if(count == 0){
            break;
        }else{
            std::vector<pcpp::RawPacket> temp{};
            std::vector<pcpp::RawPacket*>::iterator iterator = segment.begin();

            temp.reserve(1000);
            for(pcpp::RawPacket* rawPacket : segment){
                temp.emplace_back(*rawPacket);
            }
            outQueue->enqueue_bulk(temp.begin(), temp.size());

            const auto convert = [](pcpp::RawPacket* ptr){return ptr;};
            const auto vc = [&]{
                std::vector<pcpp::RawPacket>temp{segment.size()};
                std::transform(segment.begin(), segment.end(), temp.begin(), convert);
                return  temp;
            }();

            auto convert2 = [](pcpp::RawPacket* ptr){return ptr;};

            auto valueIt = boost::make_transform_iterator(segment.begin(),convert2);

            pcpp::RawPacket x = *valueIt;
            pcpp::RawPacket y = *vc.begin();
            for(const auto x : vc){

            }
            outQueue->enqueue_bulk(vc.begin(), segment.size());

        }
    }
*/
            {
                std::lock_guard <std::mutex> lock(status_mutex);
                status->at(threadID) = true;
                if (std::find(status->begin(), status->end(), false) ==
                    status->end()) {  //false cannot be found -> all other threads are finished
                    readingFinished = true;
                }
            }
            auto end = std::chrono::high_resolution_clock::now();
            readingDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            pcap_stat stats{};
            reader->getStatistics(stats);
            readPackets += stats.ps_recv;
        }
    }
}


#endif //IMPLEMENTATION_READERTHREAD_H
