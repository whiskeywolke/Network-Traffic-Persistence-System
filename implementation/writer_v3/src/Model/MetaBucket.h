//
// Created by ubuntu on 30.04.21.
//

#ifndef IMPLEMENTATION_METABUCKET_H
#define IMPLEMENTATION_METABUCKET_H

#include <vector>
#include "CompressedBucket.h"
#include <limits>
#include <string>

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>

#define METABUCKETSIZE  1000000 /// a metabucket will contain at most that much compressed bucket items

class MetaBucket {
private:

    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        storage.shrink_to_fit();
        ar & storage;
    }

    uint64_t minTimestamp;
    uint64_t maxTimestamp;
    std::vector<CompressedBucket>storage{};




public:
    MetaBucket(){
        assert(METABUCKETSIZE<storage.max_size());
        storage.reserve(METABUCKETSIZE);
        minTimestamp = std::numeric_limits<uint64_t>::max();
        maxTimestamp = 0;
    }

    bool add(const CompressedBucket& b){
        if(storage.size()<METABUCKETSIZE){
            storage.emplace_back(b);
            if(b.getMinTimestampAsInt()<minTimestamp){
                minTimestamp = b.getMinTimestampAsInt();
            }
            if(b.getMaxTimestampAsInt()>maxTimestamp){
                maxTimestamp = b.getMaxTimestampAsInt();
            }
            return true;
        }
        return false;
    }

    std::string getFileName()const{
        return std::to_string(minTimestamp) + "-" + std::to_string(maxTimestamp);
    }
    size_t size()const{
        return storage.size();
    }

};


#endif //IMPLEMENTATION_METABUCKET_H
