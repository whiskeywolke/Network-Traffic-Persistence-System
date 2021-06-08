//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_READERTHREAD_H
#define IMPLEMENTATION_READERTHREAD_H

#include "../../Common/ConcurrentQueue/concurrentqueue.h"
#include "../../Common/CompressedBucket.h"
#include "../../Common/MetaBucket.h"
#include "../Filter.h"

#include <mutex>
#include <boost/archive/binary_iarchive.hpp>

namespace reader{
    namespace threadOperations{
        void readAndFilter(std::vector<bool> &status, const int &threadID, const std::string &filePath,
                           std::vector<std::string>::const_iterator startIt,
                           const std::vector<std::string>::const_iterator &endIt,
                           const reader::TimeRangePreFilter &timeRangePreFilter, const reader::IpPreFilter &ipPreFilter,
                           moodycamel::ConcurrentQueue<common::CompressedBucket> &outQueue, std::mutex &readerStatusMutex,
                           std::atomic<bool> &filterCompressedBucketsFinished) {

            for (; startIt < endIt; ++startIt) {
                common::MetaBucket m;
                std::string fileName = filePath + *startIt;
                std::ifstream ifs(fileName);
                boost::archive::binary_iarchive ia(ifs);
                ia >> m;
                std::vector<common::CompressedBucket> temp{};
                temp.reserve(1000000);
                for (const common::CompressedBucket &c : m.getStorage()) {
                    if (timeRangePreFilter.apply(c.getMinTimestampAsInt(), c.getMaxTimestampAsInt()) &&
                        ipPreFilter.apply(c.getDict(), c.getFirstEntry().v4Src, c.getFirstEntry().v4Dst)) {
                        temp.emplace_back(c);
                    }
                }
                outQueue.enqueue_bulk(temp.begin(), temp.size());
            }
            {
                std::lock_guard<std::mutex> lock(readerStatusMutex);
                status.at(threadID) = true;
                if (std::find(status.begin(), status.end(), false) ==
                    status.end()) {  //false cannot be found -> all other threads are finished
                    filterCompressedBucketsFinished = true;
                }
            }

        }
    }
}

#endif //IMPLEMENTATION_READERTHREAD_H
