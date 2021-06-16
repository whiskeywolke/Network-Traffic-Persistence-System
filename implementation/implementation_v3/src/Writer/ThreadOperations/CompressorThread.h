//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_COMPRESSORTHREAD_H
#define IMPLEMENTATION_COMPRESSORTHREAD_H

#include "../../Common/ConcurrentQueue/concurrentqueue.h"
#include "../../Common/CompressedBucket.h"
#include "../../Common/IPTuple.h"
#include <vector>

namespace writer {
    namespace threadOperations {
        void
        compress(std::vector<bool> *status, int threadID,
                 moodycamel::ConcurrentQueue <std::vector<common::IPTuple>> *inQueue,
                 moodycamel::ConcurrentQueue <common::CompressedBucket> *outQueue, std::mutex &status_mutex,
                 std::atomic<bool> &sortingFinished, std::atomic<bool> &compressionFinished,
                 std::atomic<long> &compressionDuration) {
            auto start = std::chrono::high_resolution_clock::now();

            while (!sortingFinished || inQueue->size_approx() != 0) {
                std::vector <std::vector<common::IPTuple>> tempIn{1000};
                std::vector <common::CompressedBucket> tempOut{};
                tempOut.reserve(1000);

                size_t dequeued = inQueue->try_dequeue_bulk(tempIn.begin(), 1000);
                for (size_t i = 0; i < dequeued; ++i) {
                    common::CompressedBucket bucket;
                    for (const common::IPTuple &ipTuple : tempIn.at(i)) {
                        if (!bucket.add(ipTuple)) {//now bucket is full replace with new one & add packet to new bucket
                            tempOut.emplace_back(bucket);
                            bucket = common::CompressedBucket();
                            bucket.add(ipTuple);
                        }
                    }
                    if (bucket.getHasFirst()) { //check if bucket is not empty
                        tempOut.emplace_back(bucket);
                    }
                }
                outQueue->enqueue_bulk(tempOut.begin(), tempOut.size());


/*        std::vector<IPTuple> sorted;
        if (inQueue->try_dequeue(sorted)) {
            CompressedBucket bucket;
            for (const IPTuple &ipTuple : sorted) {
                if (!bucket.add(ipTuple)) {//now bucket is full replace with new one & add packet to new bucket
                    outQueue->enqueue(bucket);
                    bucket = CompressedBucket();
                    bucket.add(ipTuple);
                }
            }
            if (bucket.getHasFirst()) { //check if bucket is not empty
                outQueue->enqueue(bucket);
            }
        }
*/
            }
            {
                std::lock_guard <std::mutex> lock(status_mutex);
                status->at(threadID) = true;
                if (std::find(status->begin(), status->end(), false) ==
                    status->end()) {  //false cannot be found -> all other threads are finished
                    compressionFinished = true;
                }
            }

            auto end = std::chrono::high_resolution_clock::now();
            compressionDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
/*
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "compression dequeue: \t" << dequeueCounter << "\n";
        std::cout << "compression enqueue: \t" << enqueueCounter << "\n";
        std::cout<<"max offset: "<<maxmaxOffset<<std::endl;
        std::cout<<"min offset: "<<minminOffset<<std::endl;
        std::cout<<"bucket count: "<<bucketcount<<std::endl;
        std::cout<<"max port count: "<<maxObservedPorts<<std::endl;
        std::cout<<"port count more than: "<<portcountmorethan<<std::endl;
        std::cout<<"port count more than%: "<<100.0*(((double)portcountmorethan)/bucketcount)<<std::endl;
        std::cout<<"average port count: "<<observedPorts/bucketcount<<std::endl;
        std::cout<<"max ip count: "<<maxObservedIPs<<std::endl;
        std::cout<<"ip count more than: "<<ipcountmorethan<<std::endl;
        std::cout<<"ip count more than%: "<<100.0*(((double)ipcountmorethan)/bucketcount)<<std::endl;
        std::cout<<"average ip count: "<<observerdIPs/bucketcount<<std::endl;

    }
*/
        }
    }
}

#endif //IMPLEMENTATION_COMPRESSORTHREAD_H
