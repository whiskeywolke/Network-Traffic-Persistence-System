//
// Created by ubuntu on 06.04.21.
//

#ifndef PCAPPP_TEST_IPTUPLE_H
#define PCAPPP_TEST_IPTUPLE_H

#include <pcapplusplus/IpUtils.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>

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
        ar & v4Src;
        ar & v4Dst;
        ar & v6Src;
        ar & v6Dst;
        ar & portSrc;
        ar & portDst;
    }

private:
    uint8_t v4Src[4];
    uint8_t v4Dst[4];
    uint8_t v6Src[16];
    uint8_t v6Dst[16];
    uint8_t portSrc;
    uint8_t portDst;

    void setV4(const uint8_t * v4SrcI, const uint8_t * v4DstI){
        v4Src[0] = v4SrcI[0];
        v4Src[1] = v4SrcI[1];
        v4Src[2] = v4SrcI[2];
        v4Src[3] = v4SrcI[3];

        v4Dst[0] = v4DstI[0];
        v4Dst[1] = v4DstI[1];
        v4Dst[2] = v4DstI[2];
        v4Dst[3] = v4DstI[3];
    }
    void setV6(const uint8_t * v6SrcI, const uint8_t * v6DstI){
        for(short i = 0; i < 16; ++i){
            v6Src[i] = v6DstI[i];
            v6Dst[i] = v6DstI[i];
        }
    }

public:

    IPTuple() {
        setV4(pcpp::IPv4Address("127.0.0.1").toBytes(), pcpp::IPv4Address("1.1.1.1").toBytes());
        setV6(pcpp::IPv6Address("2001:0db8:3c4d:0015:0000:d234::3eee:0000").toBytes(), pcpp::IPv6Address("2001:0db8:3c4d:0015:0000:d234::3eee:0000").toBytes());
        portSrc = 0;
        portDst = 0;
    }

    IPTuple(const pcpp::IPv4Address v4SrcI, const pcpp::IPv4Address v4DstI, const uint8_t &portSrcI, const uint8_t &portDstI){
        setV4(v4SrcI.toBytes(), v4DstI.toBytes());
        this->portSrc = portSrcI;
        this->portDst = portDstI;
    }

    IPTuple(const pcpp::IPv6Address &v6SrcI, const pcpp::IPv6Address &v6DstI,  const uint8_t &portSrcI, const uint8_t &portDstI){
        setV6(v6SrcI.toBytes(),v6DstI.toBytes());
        this->portSrc = portSrcI;
        this->portDst = portDstI;
    }

    std::string toString(){
        return "Tuple: " + pcpp::IPv4Address(v4Src).toString() + " " + pcpp::IPv4Address(v4Dst).toString();
    }
    /*
    void serialize(std::ostream &os)
    {
        if (os.good())
        {
            os.write((char*)&v4Src, sizeof(v4Src));
            os.write((char*)&v4Dst, sizeof(v4Dst));
            os.write((char*)&v6Src, sizeof(v6Src));
            os.write((char*)&v6Dst, sizeof(v6Dst));
            os.write((char*)&portSrc, sizeof(portSrc));
            os.write((char*)&portDst, sizeof(portDst));
        }
    }
    static IPTuple deserialize(std::istream &is)
    {
        IPTuple retval;
        retval.v4Src = pcpp::IPv4Address("1.2.3.4");

        if (is.good())
        {
           is.read((char*)&retval.v4Src, sizeof(retval.v4Src));
            is.read((char*)&retval.v4Dst, sizeof(retval.v4Dst));
            is.read((char*)&retval.v6Src, sizeof(retval.v6Src));
            is.read((char*)&retval.v6Dst, sizeof(retval.v6Dst));
            is.read((char*)&retval.portSrc, sizeof(retval.portSrc));
            is.read((char*)&retval.portDst, sizeof(retval.portDst));
        }
        if (is.fail()) {
            throw ::std::runtime_error("failed to read full struct");
        }
        return retval;
    }
*/
    bool operator==(const IPTuple& rhs){
        return  pcpp::IPv4Address(this->v4Src) == pcpp::IPv4Address(rhs.v4Src) &&
                pcpp::IPv4Address(this->v4Dst) == pcpp::IPv4Address(rhs.v4Dst) &&
                pcpp::IPv6Address(this->v6Src) == pcpp::IPv6Address(rhs.v6Src) &&
                pcpp::IPv6Address(this->v6Dst) == pcpp::IPv6Address(rhs.v6Dst) &&
                this->portDst == rhs.portDst &&
                this->portSrc == rhs.portSrc;

    }
};


#endif //PCAPPP_TEST_IPTUPLE_H
