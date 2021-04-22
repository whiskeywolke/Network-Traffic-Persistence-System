//
// Created by ubuntu on 19.04.21.
//

#ifndef IMPLEMENTATION_AGGREGATE_H
#define IMPLEMENTATION_AGGREGATE_H

#include "IPTuple.h"
#include <map>


#include <tbb/concurrent_hash_map.h>
#include <tbb/concurrent_unordered_map.h>
#include <tbb/tbb_allocator.h>
#include <thread>

struct SortedPackets{
    IPTuple* start;
    size_t length;
};

class Aggregate2 {
private:
    //std::map<uint32_t, std::vector<IPTuple>>map{}; //TODO make map threadsafe
    //tbb::concurrent_unordered_map<uint32_t, std::vector<IPTuple>> map{};
    tbb::concurrent_hash_map<uint32_t, std::vector<IPTuple>> map{};

    mutable std::mutex mutex;
    std::thread::id minId;
    std::atomic<bool>flushing{false};


    Aggregate2() = default;;

public:

    static Aggregate2& getInstance(){
        static Aggregate2 _instance;
        return _instance;
    }

    Aggregate2(const Aggregate2&)= delete;
    Aggregate2& operator = (const Aggregate2& )  = delete;

    void setID(){
        std::lock_guard<std::mutex> lock(mutex);
        minId = std::this_thread::get_id();
        //std::cout<<"set minID: "<< this->minId<<std::endl;
    }

    bool add(IPTuple ipTuple){
        tbb::concurrent_hash_map<uint32_t, std::vector<IPTuple>>::accessor ac;
        //tbb::concurrent_unordered_map<uint32_t, std::vector<IPTuple>>::accessor ac;
        if(flushing){
            return false;
        }

        if(map.find(ac, ipTuple.getV4Src())){
            ac->second.push_back(ipTuple);
            ac.release();
            return true;
        }else if(map.find(ac,ipTuple.getV4Dst())){
            ac->second.push_back(ipTuple);
            ac.release();
            return true;
        }else{
            ac.release();
            //add new entry by source ip addr
            auto entry = std::pair<uint32_t, std::vector<IPTuple>>(ipTuple.getV4Src(), std::vector<IPTuple>{});
            entry.second.push_back(ipTuple);
            bool insertSuccess = map.insert(entry);
            //assert(insertSuccess);
            return insertSuccess;
        }
    }

    // in certain time interval write to queue
    void flush(boost::lockfree::queue<SortedPackets*>* queue){
        //since queue only supports simple dataTypes manually create arrays with "new"
        //std::cout<<"map size: "<<map.size()<<std::endl;
        if(std::this_thread::get_id() == minId) {
            //std::cout<<"I am flushing: "<< this->minId<<std::endl;

            flushing = true;
            for (auto entry : map) {
                auto *sp = new SortedPackets{};
                sp->start = new IPTuple[entry.second.size()];
                sp->length = entry.second.size();
                //std::cout<<"entry.second.size()"<<entry.second.size()<<std::endl;
                for (size_t i = 0; i < entry.second.size(); ++i) {
                    sp->start[i] = entry.second.at(i);
                }
                queue->push(sp);
            }
            map.clear();
            flushing = false;
        }
    }
};


#endif //IMPLEMENTATION_AGGREGATE_H
