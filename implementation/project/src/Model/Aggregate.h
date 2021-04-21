//
// Created by ubuntu on 19.04.21.
//

#ifndef IMPLEMENTATION_AGGREGATE_H
#define IMPLEMENTATION_AGGREGATE_H

#include "IPTuple.h"
#include <map>

struct SortedPackets{
    IPTuple* start;
    size_t length;
};

//Singleton Pattern

class Aggregate {
private:
    std::map<uint32_t, std::vector<IPTuple>>map{}; //TODO make map threadsafe

    Aggregate() = default;;

public:

    static Aggregate& getInstance(){
        static Aggregate _instance;
        return _instance;
    }

    Aggregate(const Aggregate&)= delete;
    Aggregate& operator = (const Aggregate& )  = delete;

    void add(IPTuple ipTuple){
        //std::cout<<"map size before: "<<map.size()<<std::endl;
        if(map.find(ipTuple.getV4Src()) != map.end()){
            //std::cout<<"element is there as src address\n";
            map.at(ipTuple.getV4Src()).push_back(ipTuple);

        }else if(map.find(ipTuple.getV4Dst()) != map.end()){
            //std::cout<<"element is there as dst address\n";
            map.at(ipTuple.getV4Dst()).push_back(ipTuple);
        }else{
            //add new entry by source ip addr
            auto entry = std::pair<uint32_t, std::vector<IPTuple>>(ipTuple.getV4Src(), std::vector<IPTuple>{});
            entry.second.push_back(ipTuple);
            map.insert(entry);
            //std::cout<<"element is inserted!\n";

        }
        //std::cout<<"map size after: "<<map.size()<<std::endl;
    }

    // in certain time interval write to queue
    void flush(boost::lockfree::queue<SortedPackets*>* queue){
        //since queue only supports simple dataTypes manually create arrays with "new"
        //std::cout<<"map size: "<<map.size()<<std::endl;
        for(auto entry : map){
            auto* sp = new SortedPackets{};
            sp->start = new IPTuple[entry.second.size()];
            sp->length = entry.second.size();
            //std::cout<<"entry.second.size()"<<entry.second.size()<<std::endl;
            for(size_t i = 0; i < entry.second.size();++i){
                sp->start[i] = entry.second.at(i);
            }
            queue->push(sp);
        }
        map.clear();
    }
};


#endif //IMPLEMENTATION_AGGREGATE_H
