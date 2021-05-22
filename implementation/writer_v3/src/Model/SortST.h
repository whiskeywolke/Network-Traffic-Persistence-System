//
// Created by ubuntu on 19.04.21.
//

#ifndef IMPLEMENTATION_SORT_H
#define IMPLEMENTATION_SORT_H

#include "IPTuple.h"
#include <map>
#include <mutex>
#include <unordered_map>
#include "../HashMap/robin_map.h"
#include <boost/lockfree/queue.hpp>
#include <tbb/concurrent_vector.h>
#include <tbb/concurrent_hash_map.h>
#include "../ConcurrentQueue/concurrentqueue.h"
//Singleton Pattern

class SortST {
private:
    tsl::robin_map<uint32_t, std::vector<IPTuple>> map{};

public:

    SortST() = default;;

    SortST(const SortST &) = delete;

    SortST &operator=(const SortST &) = delete;

    inline bool add(IPTuple ipTuple) {
        if (map.find(ipTuple.getV4Src()) != map.end()) {
            map.at(ipTuple.getV4Src()).emplace_back(ipTuple);
        } else if (map.find(ipTuple.getV4Dst()) != map.end()) {
            map.at(ipTuple.getV4Dst()).emplace_back(ipTuple);
        } else {
            auto newEntry = std::pair<uint32_t, std::vector<IPTuple>>(ipTuple.getV4Src(), std::vector<IPTuple>{});
            newEntry.second.reserve(1000); //reserve space for faster inserts later
            newEntry.second.emplace_back(ipTuple);
            map.insert(newEntry);
        }
        return true;
    }

    // in certain time interval write to queue
    inline void
    flush(moodycamel::ConcurrentQueue<std::vector<IPTuple>> *queue) { //queue of vectors where each vector is sorted
        for (const auto &entry : map) {
            queue->enqueue(entry.second);
        }
        map.clear();
    }

    size_t size() const {
        return map.size();
    }
};


#endif //IMPLEMENTATION_SORT_H
