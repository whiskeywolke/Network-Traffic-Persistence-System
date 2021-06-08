//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_CONVERTERTHREAD_H
#define IMPLEMENTATION_CONVERTERTHREAD_H

#include "../../Common/ConcurrentQueue/concurrentqueue.h"
#include "../../Common/IPTuple.h"
#include "../Converter.h"

namespace writer {
    namespace threadOperations {
        void convert(std::vector<bool> *status, int threadID, moodycamel::ConcurrentQueue <pcpp::RawPacket> *inQueue,
                     moodycamel::ConcurrentQueue <common::IPTuple> *outQueue, std::mutex &status_mutex,
                     std::atomic<bool> &readingFinished, std::atomic<bool> &conversionFinished,
                     std::atomic<long> &conversionDuration) {
            pcpp::RawPacket input;
            common::IPTuple ipTuple;

            auto start = std::chrono::high_resolution_clock::now();
            while (!readingFinished || inQueue->size_approx() != 0) {
/*        if (inQueue->try_dequeue(input)) {
            if (Converter::convert(input, ipTuple)) {
                outQueue->enqueue(ipTuple);
            }
        }
*/
                std::vector <pcpp::RawPacket> tempIn{1000};
                std::vector <common::IPTuple> tempOut{};
                tempOut.reserve(1000);
                size_t dequeued = inQueue->try_dequeue_bulk(tempIn.begin(), 1000);
                for (size_t i = 0; i < dequeued; ++i) {
                    if (writer::Converter::convert(tempIn.at(i), ipTuple)) {
                        tempOut.emplace_back(ipTuple);
                    }
                }
                outQueue->enqueue_bulk(tempOut.begin(), tempOut.size());
            }
            {
                std::lock_guard <std::mutex> lock(status_mutex);
                status->at(threadID) = true;
                if (std::find(status->begin(), status->end(), false) ==
                    status->end()) {  //false cannot be found -> all other threads are finished
                    conversionFinished = true;
                }
            }
            auto end = std::chrono::high_resolution_clock::now();
            conversionDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        }
    }
}

#endif //IMPLEMENTATION_CONVERTERTHREAD_H
