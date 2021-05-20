//
// Created by ubuntu on 20.04.21.
//

#ifndef IMPLEMENTATION_COMPRESSEDBUCKET_H
#define IMPLEMENTATION_COMPRESSEDBUCKET_H

#include <cstdlib>
#include "IPTuple.h"
#include "../HashMap/robin_map.h"

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
        ar & addrIndex;
        ar & isSrc;
        ar & portSrc;
        ar & portDst;
        ar & protocol;
        ar & timestamp_offset;
    }

    //uint32_t addrIndex;
    uint8_t addrIndex;
    bool isSrc;
    int32_t timestamp_offset; //needs to be at least int32 -> max pos observed offset = 1.050.534.429, min ~-1.000.000 this means cutting negative offset would not bring any meaningful improvement

    //max observed ports 9000 (14 bits)per bucket TODO add port into port with bitshift (nope dont do that)
    //less than 1% of buckets have more than 255 ports -> shrink ports to uint8_t with dictionary encoding

    uint16_t portSrc;
    uint16_t portDst;
    uint8_t protocol;

    Entry() = default;

    Entry(uint32_t v4Src, bool isSrc, int32_t timestampOffset, uint16_t portSrc, uint16_t portDst, uint8_t aProtocol)
            : addrIndex(v4Src), isSrc(isSrc), timestamp_offset(timestampOffset), portSrc(portSrc), portDst(portDst),
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
        dict.shrink_to_fit();
        entries.shrink_to_fit();

        ar & firstEntry;
        ar & entryCount;
        ar & hasFirst;
        ar & entries;
        ar & hasSecond;
        ar & matchedBySrc;
        ar & dict;
    }

    FirstEntry firstEntry;
    std::vector<Entry> entries;
    int entryCount;
    bool hasFirst;
    bool hasSecond;
    bool matchedBySrc;

 //   typedef boost::bimap< uint32_t, uint16_t > dictionary; //save an ip adress - index relation (using bimap since either value must only exist once)
 //   dictionary dict;
    //is larger than 16 bit on purpose so we can check if it is larger than allowed and then return false on insert

    //std::map<uint32_t, uint16_t>dict; //map with all ip - index pairs. note: needs to be swapped on decoding
    std::vector<uint32_t>dict;

    //TODO remove temporary observation helpers
    int32_t maxOffset = 0;
    int32_t minOffset = 0;
//    tsl::robin_map<uint16_t , int>portMap{};
    //////////////
//    CompressedBucket() = delete;

public:
    CompressedBucket() {
        firstEntry = FirstEntry();
        hasFirst = false;
        hasSecond = false;
        matchedBySrc = false;
        entries = std::vector<Entry>{};
        entryCount = 0;
    }

    //assumes that all tuples added have one matching ipv4 address
    //returns false if full = more than 255 ip addresses are associated with one single address
    bool add(const IPTuple& t) {
        if(t.getV4Src() == 0 || t.getV4Dst() == 0){
            assert(false);
        }


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
            bool saveSrcAddr{}; //this means that the src addrIndex of the new Object is different, therefore we need to save it

            //TODO simplify if else statement
            if(matchedBySrc) { //if we match by src we need to compare it to the src addrIndex since src of the first object is always equal
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
//////////////
            uint64_t a = firstEntry.timestamp;
            uint64_t b = ((t.getTvSec() * 1000000 + t.getTvUsec()));

            if(b>a && (b-a) > 0x7FFFFFFF){
                std::cout<<((t.getTvSec() * 1000000 + t.getTvUsec())  - firstEntry.timestamp)<<std::endl;
                assert(false);
            }
            if(b<a && (b-a) < 0x80000000){
                std::cout<<((t.getTvSec() * 1000000 + t.getTvUsec())  - firstEntry.timestamp)<<std::endl;
                assert(false);
            }

            //count ports
 /*           if(portMap.find(t.getPortDst()) == portMap.end()){
                auto e =  std::pair<uint16_t ,int>(t.getPortDst(), 0);
                portMap.insert(e);
            }
            if(portMap.find(t.getPortSrc()) == portMap.end()){
                auto e =  std::pair<uint16_t ,int>(t.getPortSrc(), 0);
                portMap.insert(e);
            }
*/

            int32_t timestampOffset =  (t.getTvSec() * 1000000 + t.getTvUsec()) - firstEntry.timestamp; //TODO determine timeunit of offset (nanoseconds?, should be microseconds)
   /*         if(firstEntry.timestamp<=(t.getTvSec() * 1000000 + t.getTvUsec())){
                timestampOffset = 0; //in case the packets arrive out of order the offset will be set to 0 TODO set signed in as offset
                std::cout<<"hier"<<std::endl;
            }
*/
            if(timestampOffset > maxOffset){
                maxOffset = timestampOffset;
            }
            if(timestampOffset < minOffset){
                minOffset = timestampOffset;
            }
            //assert(timestampOffset<=4294967295); //check that the offset is smaller than max value of 32 bit datatype
//////////////
            uint32_t ipAddr{};
            if(saveSrcAddr){
                ipAddr = t.getV4Src();
            }else{
                ipAddr = t.getV4Dst();
            }


            //save ip address to vector of IpAddresses
            uint32_t tempIndex = 0;
            auto it = std::find(dict.begin(), dict.end(), ipAddr);
            if(it != dict.end()){ //ipaddress already exists, find out index
                tempIndex = it - dict.begin();
                assert(tempIndex<256);
            }else{ //new ip address, needs to be added to dict
                if(dict.size() >= 256){ //already 256 (2⁸)ip adresses saved, therfore need to create new bucket
                    return false;
                }
                dict.emplace_back(ipAddr);
                tempIndex = dict.size()-1;
            }

            entries.emplace_back(
                    tempIndex,
                    saveSrcAddr,
                    timestampOffset,
                    t.getPortSrc(),
                    t.getPortDst(),
                    t.getProtocol()
                    );
            ++entryCount;
        }
        return true;
    }
    bool getHasFirst()const{
        return hasFirst;
    }

    int32_t getMaxOffset() const{
        return maxOffset;
    }
    int32_t getMinOffset() const{
        return minOffset;
    }
/*
    size_t portCount() const{
        return portMap.size();
    }
*/
    size_t ipCount() const{
        return dict.size();
    }
    struct timeval getMinTimestamp() const {
        timeval t{};
        t.tv_sec =  (firstEntry.timestamp+minOffset) / 1000000;
        t.tv_usec = (firstEntry.timestamp+minOffset) % 1000000;
        return t;
    }
    struct timeval getMaxTimestamp() const{
        timeval t{};
        t.tv_sec =  (firstEntry.timestamp+maxOffset) / 1000000;
        t.tv_usec = (firstEntry.timestamp+maxOffset) % 1000000;
        return t;
    }

    uint64_t getMinTimestampAsInt() const{
        return minOffset<0 ?  firstEntry.timestamp + minOffset : firstEntry.timestamp;
    }

    uint64_t getMaxTimestampAsInt() const{
        return firstEntry.timestamp + maxOffset;
    }

    std::vector<uint32_t>getDict() const{
        return this->dict;
    }

    void getData(std::vector<IPTuple>& res){
        if(!hasFirst){
            return;
        }
        res.reserve(entries.size()+1);
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
                    srcAddr = dict.at(e.addrIndex);
                    dstAddr = firstEntry.v4Src;
                } else {
                    srcAddr = firstEntry.v4Src;
                    dstAddr = dict.at(e.addrIndex);
                }
            }
            else{
                if(e.isSrc){
                    srcAddr = dict.at(e.addrIndex);
                    dstAddr = firstEntry.v4Dst;
                } else {
                    srcAddr = firstEntry.v4Dst;
                    dstAddr = dict.at(e.addrIndex);
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
