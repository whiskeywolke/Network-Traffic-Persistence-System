#ifndef IMPLEMENTATION_IPTUPLE_H
#define IMPLEMENTATION_IPTUPLE_H

#include <arpa/inet.h>
#include <string>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include <pcapplusplus/IpUtils.h>
#include <pcapplusplus/IPv4Layer.h>


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
        ar & length;
        ar & tv_sec;
        ar & tv_usec;
    }

private:
    uint32_t v4Src;
    uint32_t v4Dst;
    uint16_t portSrc;
    uint16_t portDst;
    uint8_t protocol;
    uint16_t length; //length in bytes
    uint64_t tv_sec; //seconds since 1.1.1970 00:00
    uint64_t tv_usec; //microseconds since last second

public:

    IPTuple() {
/*        portSrc = 0;
        portDst = 0;
        v4Src = pcpp::IPv4Address("255.255.255.255").toInt();
        v4Dst = pcpp::IPv4Address("255.255.255.255").toInt();
   */ }

    IPTuple(const pcpp::IPv4Address v4SrcI, const pcpp::IPv4Address v4DstI, const uint16_t &portSrcI, const uint16_t &portDstI, const uint8_t &protocolI, const uint16_t &lengthI, const uint64_t &tv_secI, const uint64_t &tv_usecI){
        this->v4Src = v4SrcI.toInt();
        this->v4Dst = v4DstI.toInt();
        this->portSrc = portSrcI;
        this->portDst = portDstI;
        this->protocol = protocolI;
        this->length = lengthI;
        this->tv_sec = tv_secI;
        this->tv_usec = tv_usecI;
    }

    inline uint32_t getV4Src() const {
        return v4Src;
    }

    inline uint32_t getV4Dst() const {
        return v4Dst;
    }

    inline uint16_t getPortSrc() const {
        return portSrc;
    }

    inline uint16_t getPortDst() const {
        return portDst;
    }

    inline uint8_t getProtocol() const {
        return protocol;
    }

    inline uint64_t getTvSec() const {
        return tv_sec;
    }

    inline uint64_t getTvUsec() const {
        return tv_usec;
    }

    inline uint16_t getLength() const {
        return length;
    }

    std::string toString(){
        return pcpp::IPv4Address(v4Src).toString() + ":" + std::to_string(portSrc) + " \t" + pcpp::IPv4Address(v4Dst).toString() + ":" + std::to_string(portDst) + " " +
                std::to_string(protocol) + " " + std::to_string(length) + " " + std::to_string(tv_sec) + " " + std::to_string(tv_usec);
    }

    bool operator==(const IPTuple& rhs) const{
        return this->v4Src == rhs.v4Src &&
               this->v4Dst == rhs.v4Dst &&
                this->portDst == rhs.portDst &&
                this->portSrc == rhs.portSrc &&
                this->length == rhs.length &&
                this->tv_sec == rhs.tv_sec &&
                this->tv_usec == rhs.tv_usec;

    }
};
#endif //IMPLEMENTATION_IPTUPLE_H
