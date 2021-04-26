//
// Created by ubuntu on 19.04.21.
//

#ifndef IMPLEMENTATION_AGGREGATE_H
#define IMPLEMENTATION_AGGREGATE_H

#include "IPTuple.h"
#include <map>
#include <mutex>
#include <unordered_map>
#include "../HashMap/robin_map.h"
#include <boost/lockfree/queue.hpp>
#include <tbb/concurrent_vector.h>
#include <tbb/concurrent_hash_map.h>
//Singleton Pattern

class Aggregate3 {
private:
    //std::map<uint32_t, std::vector<IPTuple>>map{}; //TODO make map threadsafe
    //std::unordered_map<>
    tsl::robin_map<uint32_t, tbb::concurrent_vector<IPTuple>>map{};
    //std::unordered_map<uint32_t, tbb::concurrent_vector<IPTuple>>map{};


    mutable std::mutex mutex;
    std::thread::id minId;
    std::atomic<bool>flushing{false};

    Aggregate3() = default;;

public:

    static Aggregate3& getInstance(){
        static Aggregate3 _instance;
        return _instance;
    }

    Aggregate3(const Aggregate3&)= delete;
    Aggregate3& operator = (const Aggregate3& )  = delete;

    void setID(){
        std::lock_guard<std::mutex> lock(mutex);
        minId = std::this_thread::get_id();
    }

    bool add(IPTuple ipTuple){
        if(flushing){
            return false;
        }
        if(map.find(ipTuple.getV4Src()) != map.end()){
            try {
                map.at(ipTuple.getV4Src()).emplace_back(ipTuple);
            }catch(...){
                std::cerr<<"error hier1\n";
            }
        }else if(map.find(ipTuple.getV4Dst()) != map.end()){
            try {
                map.at(ipTuple.getV4Dst()).emplace_back(ipTuple);
            }catch(...){
                std::cerr<<"error hier2\n";
            }
        }else{
            std::lock_guard<std::mutex>lock(mutex);  //map itself is not thread safe, therefore lock before adding insert

            auto newEntry = std::pair<uint32_t, tbb::concurrent_vector<IPTuple>>(ipTuple.getV4Src(), tbb::concurrent_vector<IPTuple>{});
            newEntry.second.emplace_back(ipTuple);
            map.insert(newEntry);

        }
        return true;
    }


    // in certain time interval write to queue
    void flush(moodycamel::ConcurrentQueue<tbb::concurrent_vector<IPTuple>>* queue){ //queue of queues where each inner queue is sorted
        if(std::this_thread::get_id() == minId) {
            flushing = true;
            for (const auto& entry : map) {
                queue->enqueue(entry.second);
            }
            map.clear();
            flushing = false;
        }
    }
};


#endif //IMPLEMENTATION_AGGREGATE_H
