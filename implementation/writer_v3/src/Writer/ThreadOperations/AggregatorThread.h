//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_AGGREGATORTHREAD_H
#define IMPLEMENTATION_AGGREGATORTHREAD_H

#include "../../Common/ConcurrentQueue/concurrentqueue.h"
#include "../../Common/CompressedBucket.h"
#include "../../Common/MetaBucket.h"

namespace writer {
    namespace threadOperations {
        void aggregate(std::vector<bool> *status, int threadID,
                       moodycamel::ConcurrentQueue <common::CompressedBucket> *inQueue,
                       moodycamel::ConcurrentQueue <common::MetaBucket> *outQueue, std::mutex &status_mutex,
                       std::atomic<bool> &compressionFinished, std::atomic<bool> &aggregationFinished,
                       std::atomic<long> &aggregationDuration) {
            auto start = std::chrono::high_resolution_clock::now();

            common::MetaBucket meta{};
            auto metaLifetime = std::chrono::high_resolution_clock::now();
            std::vector <common::CompressedBucket> tempIn{1000};

            while (!compressionFinished || inQueue->size_approx() != 0) {

                size_t dequeued = inQueue->try_dequeue_bulk(tempIn.begin(), 1000);
                for (size_t i = 0; i < dequeued; ++i) {
                    if (!meta.add(
                            tempIn.at(i))) { //metabucket is full, enqeue full one and replace with new metabucket,
                        if (outQueue->enqueue(meta)) {
                            meta = common::MetaBucket();
                            metaLifetime = std::chrono::high_resolution_clock::now();
                            meta.add(tempIn.at(i));
                        }
                    }
                    auto current_time = std::chrono::high_resolution_clock::now();
                    if (std::chrono::duration_cast<std::chrono::seconds>(current_time - metaLifetime).count() >=
                        10) { //metabucket lives already to long
                        if (outQueue->enqueue(meta)) {
                            meta = common::MetaBucket();
                            metaLifetime = current_time;
                        }
                    }
                }

/*
        CompressedBucket b;
        if (inQueue->try_dequeue(b)) {
            if (!meta.add(b)) { //metabucket is full
                if (outQueue->enqueue(meta)) {
                    meta = MetaBucket();
                    metaLifetime = std::chrono::high_resolution_clock::now();
                }
            }
            auto current_time = std::chrono::high_resolution_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(current_time - metaLifetime).count() >=
                10) { //metabucket lives already to long
                if (outQueue->enqueue(meta)) {
                    meta = MetaBucket();
                    metaLifetime = current_time;
                }
            }
        }
*/
            }
            if (meta.size() != 0) {
                while (!outQueue->enqueue(meta)); //enqueue last metabucket
            }
            {
                std::lock_guard <std::mutex> lock(status_mutex);
                status->at(threadID) = true;
                if (std::find(status->begin(), status->end(), false) ==
                    status->end()) {  //false cannot be found -> all other threads are finished
                    aggregationFinished = true;
                }
            }
            auto end = std::chrono::high_resolution_clock::now();
            aggregationDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        }


    }
}

#endif //IMPLEMENTATION_AGGREGATORTHREAD_H
