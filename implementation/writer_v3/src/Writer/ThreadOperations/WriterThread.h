//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_WRITERTHREAD_H
#define IMPLEMENTATION_WRITERTHREAD_H

#include "../../Common/ConcurrentQueue/concurrentqueue.h"
#include "../../Common/MetaBucket.h"
#include <boost/archive/binary_oarchive.hpp>

namespace writer {
    namespace threadOperations {
        void
        writeToFile(std::vector<bool> *status, int threadID, moodycamel::ConcurrentQueue <common::MetaBucket> *inQueue,
                    const std::string &outFilePath, std::atomic<bool> &aggregationFinished,
                    std::atomic<long> &writingDuration) {
            auto start = std::chrono::high_resolution_clock::now();
            {
                common::MetaBucket b;
                while (!aggregationFinished || inQueue->size_approx() != 0) {
                    if (inQueue->try_dequeue(b)) {
                        std::string outFileName = outFilePath + b.getFileName() + ".bin";
                        std::ofstream ofs(outFileName);
                        boost::archive::binary_oarchive oa(ofs);
                        oa << b;
                    }
                }
            }
            auto end = std::chrono::high_resolution_clock::now();
            writingDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        }
    }
}

#endif //IMPLEMENTATION_WRITERTHREAD_H
