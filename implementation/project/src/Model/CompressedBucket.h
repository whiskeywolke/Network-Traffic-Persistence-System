//
// Created by ubuntu on 20.04.21.
//

#ifndef IMPLEMENTATION_COMPRESSEDBUCKET_H
#define IMPLEMENTATION_COMPRESSEDBUCKET_H

#include <cstdlib>
#include "IPTuple.h"

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>


struct FirstEntry{

    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & v4Dst;
        ar & v4Src;
        ar & portSrc;
        ar & portDst;
        ar & protocol;
        ar & timestamp;
    }

    uint32_t v4Src;
    uint32_t v4Dst;
    uint16_t portSrc;
    uint16_t portDst;
    uint8_t protocol;

    u_int64_t timestamp;

    FirstEntry() = default;

    FirstEntry(uint32_t v4Src, uint32_t v4Dst, uint16_t portSrc, uint16_t portDst, uint8_t aProtocol,
               u_int64_t timestamp) : v4Src(v4Src), v4Dst(v4Dst), portSrc(portSrc), portDst(portDst),
                                      protocol(aProtocol), timestamp(timestamp) {}
};

struct Entry{

    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & addr;
        ar & isSrc;
        ar & portSrc;
        ar & portDst;
        ar & protocol;
        ar & timestamp_offset;
    }

    uint32_t addr;
    bool isSrc;
    u_int32_t timestamp_offset;

    uint16_t portSrc;
    uint16_t portDst;
    uint8_t protocol;

    Entry() = default;

    Entry(uint32_t v4Src, bool isSrc, u_int32_t timestampOffset, uint16_t portSrc, uint16_t portDst, uint8_t aProtocol)
            : addr(v4Src), isSrc(isSrc), timestamp_offset(timestampOffset), portSrc(portSrc), portDst(portDst),
              protocol(aProtocol) {}
};


class CompressedBucket {
    //dictionary encoding for IP adress, +1 byte if src or dst, other IP adress is always equal
    //delta encoding for timestamp

    //what to do with protocol?
    //what to do with

private:

    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & firstEntry;
        ar & entryCount;
        ar & hasFirst;
        ar & entries;
    }

    FirstEntry firstEntry;
    std::vector<Entry> entries;
    int entryCount;
    bool hasFirst;

//    CompressedBucket() = delete;

public:
    CompressedBucket() {
        hasFirst = false;
        entries = std::vector<Entry>{};
        entryCount = 0;
    }


    void add(IPTuple t) {
        if(!hasFirst) {
            u_int64_t timestamp = (unsigned long) t.getTvSec() * 1000000 + t.getTvUsec();
            firstEntry = FirstEntry(
                    t.getV4Src(),
                    t.getV4Dst(),
                    t.getPortSrc(),
                    t.getPortDst(),
                    t.getProtocol(),
                    timestamp
                    );
            hasFirst = true;
        }
        else{
            bool isSrc = false;
            isSrc = firstEntry.v4Dst == t.getV4Dst();
            uint32_t timestampOffset = (uint32_t) firstEntry.timestamp - (unsigned long) t.getTvSec() * 1000000 + t.getTvUsec();
            entries.emplace_back(
                            t.getV4Src(),
                            isSrc,
                            timestampOffset,
                            t.getPortSrc(),
                            t.getPortDst(),
                            t.getProtocol()

                    );
            ++entryCount;
        }
    }
};


#endif //IMPLEMENTATION_COMPRESSEDBUCKET_H
