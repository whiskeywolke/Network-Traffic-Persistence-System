//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_FILTERTHREAD_H
#define IMPLEMENTATION_FILTERTHREAD_H

namespace reader{
    namespace threadOperations{
        void filterIpTuples(std::vector<bool> &status, const int &threadID, const reader::AndFilter &filter,
                            moodycamel::ConcurrentQueue<common::CompressedBucket> &inQueue,
                            moodycamel::ConcurrentQueue<common::IPTuple> &outQueue, std::mutex &filterStatusMutex,
                            std::atomic<bool> &filterCompressedBucketsFinished, std::atomic<bool> &filterIpTuplesFinished) {

            while (!filterCompressedBucketsFinished || inQueue.size_approx() != 0) {
                common::CompressedBucket c;
                std::vector<common::IPTuple> temp{};

                if (inQueue.try_dequeue(c)) {
                    std::vector<common::IPTuple> decompressed{};
                    c.getData(decompressed);
                    temp.reserve(decompressed.size());
                    for (const common::IPTuple &t : decompressed) {
                        if (filter.apply(t)) {
                            temp.emplace_back(t);
                        }
                    }
                    outQueue.enqueue_bulk(temp.begin(), temp.size());
                    temp.clear();
                }
            }
            {
                std::lock_guard<std::mutex> lock(filterStatusMutex);
                status.at(threadID) = true;
                if (std::find(status.begin(), status.end(), false) ==
                    status.end()) {  //false cannot be found -> all other threads are finished
                    filterIpTuplesFinished = true;
                }
            }
        }
    }
}

#endif //IMPLEMENTATION_FILTERTHREAD_H
