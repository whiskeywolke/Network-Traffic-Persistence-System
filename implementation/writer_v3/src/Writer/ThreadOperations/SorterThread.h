//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_SORTERTHREAD_H
#define IMPLEMENTATION_SORTERTHREAD_H

#include "../../Common/ConcurrentQueue/concurrentqueue.h"
#include "../../Common/IPTuple.h"
#include "../SortST.h"
#include <vector>

namespace writer {
    namespace threadOperations {
        void sortSingleThread(std::vector<bool> *status, int threadID,
                              moodycamel::ConcurrentQueue <common::IPTuple> *inQueue,
                              moodycamel::ConcurrentQueue <std::vector<common::IPTuple>> *outQueue,
                              std::mutex &status_mutex,
                              std::atomic<bool> &conversionFinished, std::atomic<bool> &sortingFinished,
                              std::atomic<long> &sortingDuration) {
            writer::SortST b{};
            auto start = std::chrono::high_resolution_clock::now();
            auto time_since_flush = std::chrono::high_resolution_clock::now();
            while (!conversionFinished || inQueue->size_approx() != 0) {
/*
        IPTuple t;
        if (inQueue->try_dequeue(t)) {
            while (!b.add(t)) {}
        }
*/
                std::vector <common::IPTuple> tempIn{1000};
                size_t dequeued = inQueue->try_dequeue_bulk(tempIn.begin(), 1000);
                for (size_t i = 0; i < dequeued; ++i) {
                    while (!b.add(tempIn.at(i))) {}
                }

                auto current_time = std::chrono::high_resolution_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(current_time - time_since_flush).count() >= 2) {
                    b.flush(outQueue);
                    time_since_flush = current_time;
                }
            }
            b.flush(outQueue);
            {
                std::lock_guard <std::mutex> lock(status_mutex);
                status->at(threadID) = true;
                if (std::find(status->begin(), status->end(), false) ==
                    status->end()) {  //false cannot be found -> all other threads are finished
                    sortingFinished = true;
                }
            }
            auto end = std::chrono::high_resolution_clock::now();
            sortingDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        }
    }
}

#endif //IMPLEMENTATION_SORTERTHREAD_H
