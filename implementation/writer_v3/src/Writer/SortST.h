//
// Created by ubuntu on 19.04.21.
//

#ifndef IMPLEMENTATION_SORT_H
#define IMPLEMENTATION_SORT_H

#include "../Common/IPTuple.h"
#include <map>
#include <mutex>
#include <unordered_map>
#include "HashMap/robin_map.h"
#include "../Common/ConcurrentQueue/concurrentqueue.h"

#define BOOST_RESULT_OF_USE_DECLTYPE

#include <boost/iterator/transform_iterator.hpp>

namespace writer {
    class SortST {
    private:
        tsl::robin_map<uint32_t, std::vector<common::IPTuple>> map{};

    public:

        SortST() = default;;

        SortST(const SortST &) = delete;

        SortST &operator=(const SortST &) = delete;

        inline bool add(const common::IPTuple &ipTuple) {
            if (map.find(ipTuple.getV4Src()) != map.end()) {
                map.at(ipTuple.getV4Src()).emplace_back(ipTuple);
            } else if (map.find(ipTuple.getV4Dst()) != map.end()) {
                map.at(ipTuple.getV4Dst()).emplace_back(ipTuple);
            } else {
                auto newEntry = std::pair<uint32_t, std::vector<common::IPTuple>>(ipTuple.getV4Src(),
                                                                                  std::vector<common::IPTuple>{});
                newEntry.second.reserve(1000); //reserve space for faster inserts later
                newEntry.second.emplace_back(ipTuple);
                map.insert(newEntry);
            }
            return true;
        }

        // in certain time interval write to queue
        inline void
        flush(moodycamel::ConcurrentQueue<std::vector<common::IPTuple>> *queue) { //queue of vectors where each vector is sorted
            auto value = [](const std::pair<uint32_t, std::vector<common::IPTuple>> &entry) { return entry.second; };
            auto valueIt = boost::make_transform_iterator(map.begin(), value);
            queue->enqueue_bulk(valueIt, map.size());
/*
        for (const auto &entry : map) {
            queue->enqueue(entry.second);
        }
*/
            map.clear();
        }

        size_t size() const {
            return map.size();
        }
    };
}

#endif //IMPLEMENTATION_SORT_H
