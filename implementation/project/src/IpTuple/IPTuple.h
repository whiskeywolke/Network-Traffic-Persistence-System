#ifndef IMPLEMENTATION_IPTUPLE_H
#define IMPLEMENTATION_IPTUPLE_H

#include <pcapplusplus/IpUtils.h>
#include <pcapplusplus/IPv4Layer.h>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include <string>

class IPTuple {
    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & v4Dst;
        ar & v4Src;
        ar & portSrc;
        ar & portDst;
        ar & protocol;
    }

private:
    uint32_t v4Src;
    uint32_t v4Dst;
    uint16_t portSrc;
    uint16_t portDst;
    uint8_t protocol;

public:

    IPTuple() {
        portSrc = 0;
        portDst = 0;
        v4Src = pcpp::IPv4Address("127.0.0.1").toInt();
        v4Src = pcpp::IPv4Address("1.1.1.1").toInt();
    }

    IPTuple(const pcpp::IPv4Address v4SrcI, const pcpp::IPv4Address v4DstI, const uint8_t &portSrcI, const uint8_t &portDstI){
        this->v4Src = v4SrcI.toInt();
        this->v4Dst = v4DstI.toInt();
        this->portSrc = portSrcI;
        this->portDst = portDstI;
    }

    uint32_t getV4Src() const {
        return v4Src;
    }

    uint32_t getV4Dst() const {
        return v4Dst;
    }

    uint16_t getPortSrc() const {
        return portSrc;
    }

    uint16_t getPortDst() const {
        return portDst;
    }

    uint8_t getAProtocol() const {
        return protocol;
    }


    std::string toString(){
     return "Tuple: " + std::to_string(v4Src) + " " + std::to_string(v4Dst);
    }

    bool operator==(const IPTuple& rhs){
        return this->v4Src == rhs.v4Src &&
               this->v4Dst == rhs.v4Dst &&
                this->portDst == rhs.portDst &&
                this->portSrc == rhs.portSrc;

    }
};
#endif //PCAPPP_TEST_IPTUPLE_H
