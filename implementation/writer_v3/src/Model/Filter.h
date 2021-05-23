//
// Created by ubuntu on 23.05.21.
//

#ifndef IMPLEMENTATION_FILTER_H
#define IMPLEMENTATION_FILTER_H


#include <string>
#include "IPTuple.h"
/*    uint32_t v4Src;
    uint32_t v4Dst;
    uint16_t portSrc;
    uint16_t portDst;
    uint8_t protocolId;
    uint16_t length; //length in bytes
    uint64_t tv_sec; //seconds since 1.1.1970 00:00
    uint64_t tv_usec; //microseconds since last second
*/

enum Operator{
    equal,
    notEqual,
    lessThan,
    greaterThan,
    lessThanEqual,
    greaterThanEqual,
};
static const char *operatorStr[] = {
        "==", "!=", "<", ">", "<=", ">="
};

class Filter {
public:
    virtual bool apply(const IPTuple& t) = 0;
    virtual std::string toString() = 0;
};

class AndFilter : public Filter{ // everything must apply to pass this filter, every filter can only have one instance of one filterable object
    std::vector<Filter*>filters{};
public:
    AndFilter() = default;
    void addFilter(Filter* filter){
        filters.push_back(filter);
    }
    bool apply(const IPTuple& t){
        for(auto f : filters){
            if(!f->apply(t)){
                return false;
            }
        }
        return true;
    }
    std::string toString(){
        return "AndFilter";
    }

};

class OrFilter : public Filter{ //only one element of filter must apply
private:
    std::vector<Filter*>filters{};
public:
    OrFilter() = default;
    void addFilter(Filter* filter){
        filters.push_back(filter);
    }
    bool apply(const IPTuple& t){
        for(auto f : filters){
            if(f->apply(t)){
                return true;
            }
        }
        return false;
    }
    std::string toString(){
        return "OrFilter";
    }
};

class SrcIPFilter : public Filter{ //filters for src OR dst ip address
private:
    uint32_t addr;
    Operator op;
public:
    SrcIPFilter(uint32_t addr, Operator op): addr(addr), op(op) {}
    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal: return t.getV4Src() == addr;
            case notEqual: return t.getV4Src() != addr;
            case lessThan: return t.getV4Src() < addr;
            case greaterThan: return t.getV4Src() > addr;
            case lessThanEqual: return t.getV4Src() <= addr;
            case greaterThanEqual: return t.getV4Src() >= addr;
            default: return false;
        }
    }
    std::string toString() override {
        return "SrcIPFilter " + std::string (operatorStr[op]) + std::to_string(addr);
    }
};

class DstIPFilter : public Filter{ //filters for src OR dst ip address
private:
    uint32_t addr;
    Operator op;
public:
    DstIPFilter(uint32_t addr, Operator op): addr(addr), op(op) {}
    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal: return t.getV4Dst() == addr;
            case notEqual: return t.getV4Dst() != addr;
            case lessThan: return t.getV4Dst() < addr;
            case greaterThan: return t.getV4Dst() > addr;
            case lessThanEqual: return t.getV4Dst() <= addr;
            case greaterThanEqual: return t.getV4Dst() >= addr;
            default: return false;
        }
    }
    std::string toString() override {
        return "DstIPFilter " + std::string (operatorStr[op]) + std::to_string(addr);
    }
};

class IPFilter : public Filter{ //filters for src OR dst ip address
    uint32_t addr;
    Operator op;
public:
    IPFilter(uint32_t addr, Operator op) : addr(addr), op(op) {}
    bool apply(const IPTuple &t) override {
        return SrcIPFilter{addr, op}.apply(t) || DstIPFilter{addr,op}.apply(t);
    }
    std::string toString() override {
        return "IPFilter";
    }
};

class SrcPortFilter : public Filter{
private:
    uint16_t port;
    Operator op;
public:
    SrcPortFilter(uint16_t port, Operator op): port(port), op(op) {}
    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal: return t.getPortSrc() == port;
            case notEqual: return t.getPortSrc() != port;
            case lessThan: return t.getPortSrc() < port;
            case greaterThan: return t.getPortSrc() > port;
            case lessThanEqual: return t.getPortSrc() <= port;
            case greaterThanEqual: return t.getPortSrc() >= port;
            default: return false;
        }
    }
    std::string toString() override {
        return "SrcPortFilter " + std::string (operatorStr[op]) + std::to_string(port);
    }
};

class DstPortFilter : public Filter{
private:
    uint16_t port;
    Operator op;
public:
    DstPortFilter(uint16_t port, Operator op): port(port), op(op) {}
    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal: return t.getPortDst() == port;
            case notEqual: return t.getPortDst() != port;
            case lessThan: return t.getPortDst() < port;
            case greaterThan: return t.getPortDst() > port;
            case lessThanEqual: return t.getPortDst() <= port;
            case greaterThanEqual: return t.getPortDst() >= port;
            default: return false;
        }
    }
    std::string toString() override {
        return "DstPortFilter: " + std::string (operatorStr[op]) + std::to_string(port);
    }
};

class PortFilter : public Filter{ //filters for src OR dst ip address
    uint16_t port;
    Operator op;
public:
    PortFilter(uint16_t port, Operator op) : port(port), op(op) {}
    bool apply(const IPTuple &t) override {
        return SrcPortFilter{port, op}.apply(t) || DstPortFilter{port,op}.apply(t);
    }
    std::string toString() override {
        return "PortFilter";
    }
};

class ProtocolFilter : public Filter{
private:
    uint8_t protocolId;
    Operator op;
public:
    ProtocolFilter(uint8_t protocolId, Operator op): protocolId(protocolId), op(op) {}
    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal: return t.getProtocol() == protocolId;
            case notEqual: return t.getProtocol() != protocolId;
            case lessThan: return t.getProtocol() < protocolId;
            case greaterThan: return t.getProtocol() > protocolId;
            case lessThanEqual: return t.getProtocol() <= protocolId;
            case greaterThanEqual: return t.getProtocol() >= protocolId;
            default: return false;
        }
    }
    std::string toString() override {
        return "ProtocolFilter: " + std::string (operatorStr[op]) + std::to_string(protocolId);
    }
};

class LengthFilter : public Filter{
private:
    uint16_t length;
    Operator op;
public:
    LengthFilter(uint16_t length, Operator op): length(length), op(op) {}
    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal: return t.getLength() == length;
            case notEqual: return t.getLength() != length;
            case lessThan: return t.getLength() < length;
            case greaterThan: return t.getLength() > length;
            case lessThanEqual: return t.getLength() <= length;
            case greaterThanEqual: return t.getLength() >= length;
            default: return false;
        }
    }
    std::string toString() override {
        return "ProtocolFilter: " + std::string (operatorStr[op]) + std::to_string(length);
    }
};

class TimeFilter : public Filter{
private:
    timeval time;
    Operator op;
public:
    TimeFilter(timeval time, Operator op): time(time), op(op) {}
    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal: return t.getTvSec() == time.tv_sec && t.getTvUsec() == time.tv_usec;
            case notEqual: return t.getTvSec() != time.tv_sec || t.getTvUsec() != time.tv_usec;
            case lessThan: return t.getTvSec() <= time.tv_sec && t.getTvUsec() < time.tv_usec;
            case greaterThan: return t.getTvSec() >= time.tv_sec && t.getTvUsec() > time.tv_usec;
            case lessThanEqual: return t.getTvSec() <= time.tv_sec && t.getTvUsec() <= time.tv_usec;
            case greaterThanEqual: return t.getTvSec() >= time.tv_sec  && t.getTvUsec() >= time.tv_usec;
            default: return false;
        }
    }
    std::string toString() override {
        return "TimeFilter: " + std::string (operatorStr[op]) + std::to_string(time.tv_sec) + " " + std::to_string(time.tv_usec);
    }
};

#endif //IMPLEMENTATION_FILTER_H
