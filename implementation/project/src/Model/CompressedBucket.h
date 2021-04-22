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
    uint32_t timestamp_offset;

    uint16_t portSrc;
    uint16_t portDst;
    uint8_t protocol;

    Entry() = default;

    Entry(uint32_t v4Src, bool isSrc, uint32_t timestampOffset, uint16_t portSrc, uint16_t portDst, uint8_t aProtocol)
            : addr(v4Src), isSrc(isSrc), timestamp_offset(timestampOffset), portSrc(portSrc), portDst(portDst),
              protocol(aProtocol) {}
};


class CompressedBucket {
    //dictionary encoding for IP adress, +1 byte if src or dst, other IP adress is always equal
    //delta encoding for timestamp

    //what to do with protocol?
    //what to do with port?

private:

    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & firstEntry;
        ar & entryCount;
        ar & hasFirst;
        ar & entries;
        ar & hasSecond;
        ar & matchedBySrc;
    }

    FirstEntry firstEntry;
    std::vector<Entry> entries;
    int entryCount;
    bool hasFirst;
    bool hasSecond;
    bool matchedBySrc;

//    CompressedBucket() = delete;

public:
    CompressedBucket() {
        hasFirst = false;
        hasSecond = false;
        matchedBySrc = false;
        entries = std::vector<Entry>{};
        entryCount = 0;
    }

    //assumes that all tuples added have one matching ipv4 address
    void add(IPTuple t) {
        if(!hasFirst) {
            u_int64_t timestamp = t.getTvSec() * 1000000 + t.getTvUsec();
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
            if(!hasSecond){
                //find out which ipaddress is the same (needed for decompression)
                if(firstEntry.v4Src==t.getV4Src() || firstEntry.v4Src==t.getV4Dst()) { //this means that the src of the first element address is equal in all others
                    matchedBySrc = true;
                }
                else {
                    matchedBySrc = false;
                }
                hasSecond = true;

                //TODO remove asserts
                if(matchedBySrc)
                    assert(firstEntry.v4Src==t.getV4Src() || firstEntry.v4Src==t.getV4Dst());
                else
                    assert(firstEntry.v4Dst==t.getV4Src() || firstEntry.v4Dst==t.getV4Dst());
            }
            bool saveSrcAddr{}; //this means that the src addr of the new Object is different, therefore we need to save it

            //TODO simplify if else statement
            if(matchedBySrc) { //if we match by src we need to compare it to the src addr since src of the first object is always equal
                if (t.getV4Src() == firstEntry.v4Src) { //the src of the new object is equal to src therefore save dst
                    saveSrcAddr = false;
                } else if (t.getV4Dst() == firstEntry.v4Src) { //dst of the new object is equal to dst therefore save src
                    saveSrcAddr = true;
                }else{
                    std::cout<<"nothing equal"<<std::endl;
                    assert(false);
                }
            }else{
                if (t.getV4Src() == firstEntry.v4Dst) { //the src of the new object is equal to src therefore save dst
                    saveSrcAddr = false;
                } else if (t.getV4Dst() == firstEntry.v4Dst) { //dst of the new object is equal to dst therefore save src
                    saveSrcAddr = true;
                }else{
                    std::cout<<"nothing equal"<<std::endl;
                    assert(false);
                }
            }

  //          if(firstEntry.timestamp>(t.getTvSec() * 1000000 + t.getTvUsec())){
  //              std::cout<<firstEntry.timestamp<<" "<<(t.getTvSec() * 1000000 + t.getTvUsec())<<std::endl;
  //          }

            //assert(firstEntry.timestamp<=(t.getTvSec() * 1000000 + t.getTvUsec())); //check that we dont get an overflow and an invalid offset

            uint32_t timestampOffset =  (t.getTvSec() * 1000000 + t.getTvUsec()) - firstEntry.timestamp;
            if(firstEntry.timestamp<=(t.getTvSec() * 1000000 + t.getTvUsec())){
                timestampOffset = 0; //in case the packets arrive out of order the offset will be set to 0 TODO set signed in as offset
            }

            assert(timestampOffset<=4294967295); //check that the offset is smaller than max value of 32 bit datatype

            uint32_t ipAddr{};
            if(saveSrcAddr){
                ipAddr = t.getV4Src();
            }else{
                ipAddr = t.getV4Dst();
            }

            entries.emplace_back(
                    ipAddr,
                    saveSrcAddr,
                    timestampOffset,
                    t.getPortSrc(),
                    t.getPortDst(),
                    t.getProtocol()
                    );
            ++entryCount;
        }
    }

    void getData(std::vector<IPTuple>& res){
        if(!hasFirst){
            return;
        }
        //make IPTuple from first element
        uint64_t timestamp_sec =  firstEntry.timestamp / 1000000;
        uint64_t timestamp_usec = firstEntry.timestamp % 1000000;

        IPTuple t{pcpp::IPv4Address(firstEntry.v4Src),
                  pcpp::IPv4Address(firstEntry.v4Dst),
                  firstEntry.portSrc,
                  firstEntry.portDst,
                  firstEntry.protocol,
                  timestamp_sec,
                  timestamp_usec};

        res.emplace_back(t);

        //make IPTuple from other elements
        for(Entry e : entries){
            uint32_t srcAddr{};
            uint32_t dstAddr{};
            if(matchedBySrc) {
                if (e.isSrc) {
                    srcAddr = e.addr;
                    dstAddr = firstEntry.v4Src;
                } else {
                    srcAddr = firstEntry.v4Src;
                    dstAddr = e.addr;
                }
            }
            else{
                if(e.isSrc){
                    srcAddr = e.addr;
                    dstAddr = firstEntry.v4Dst;
                } else {
                    srcAddr = firstEntry.v4Dst;
                    dstAddr = e.addr;
                }
            }
            timestamp_sec =  (firstEntry.timestamp+e.timestamp_offset) / 1000000;
            timestamp_usec = (firstEntry.timestamp+e.timestamp_offset) % 1000000;

            IPTuple x{
                pcpp::IPv4Address(srcAddr),
                pcpp::IPv4Address(dstAddr),
                e.portSrc,
                e.portDst,
                e.protocol,
                timestamp_sec,
                timestamp_usec
            };
            res.emplace_back(x);
        }
    }

};


#endif //IMPLEMENTATION_COMPRESSEDBUCKET_H
