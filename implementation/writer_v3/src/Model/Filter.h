//
// Created by ubuntu on 23.05.21.
//

#ifndef IMPLEMENTATION_FILTER_H
#define IMPLEMENTATION_FILTER_H


#include <string>
#include <regex>
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

enum Operator {
    equal,
    notEqual,
    lessThan,
    greaterThan,
    lessThanEqual,
    greaterThanEqual,
};
/*static const char *operatorType[] = {
        "==", "!=", "<", ">", "<=", ">="
};
*/
static const std::vector<std::string> operatorType = {
        "==", "!=", "<", ">", "<=", ">="
};

class Filter {
public:
    virtual bool apply(const IPTuple &t) = 0;

    virtual std::string toString() = 0;
};

class BoolFilter : public Filter {
public:
    virtual void addFilter(Filter *filter) = 0;
};

class AndFilter
        : public BoolFilter { // everything must apply to pass this filter, every filter can only have one instance of one filterable object
    std::vector<Filter *> filters{};
public:
    AndFilter() = default;

    void addFilter(Filter *filter) {
        filters.push_back(filter);
    }

    bool apply(const IPTuple &t) override {
        for (auto f : filters) {
            if (!f->apply(t)) {
                return false;
            }
        }
        return true;
    }

    std::string toString() override {
        std::string s = "(";
        for (size_t i = 0; i < filters.size(); ++i) {
            if (i > 0) {
                s += " and ";
            }
            s += filters.at(i)->toString();
        }
        s += ")";
        return s;
    }

};

class OrFilter : public BoolFilter { //only one element of filter must apply
private:
    std::vector<Filter *> filters{};
public:
    OrFilter() = default;

    void addFilter(Filter *filter) {
        filters.push_back(filter);
    }

    bool apply(const IPTuple &t) override {
        for (auto f : filters) {
            if (f->apply(t)) {
                return true;
            }
        }
        return false;
    }

    std::string toString() override {
        std::string s = "(";
        for (size_t i = 0; i < filters.size(); ++i) {
            if (i > 0) {
                s += " or ";
            }
            s += filters.at(i)->toString();
        }
        s += ")";
        return s;
    }
};

class SrcIPFilter : public Filter { //filters for src OR dst ip address
private:
    uint32_t addr;
    Operator op;
public:
    SrcIPFilter(uint32_t addr, Operator op) : addr(addr), op(op) {}

    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal:
                return t.getV4Src() == addr;
            case notEqual:
                return t.getV4Src() != addr;
            case lessThan:
                return t.getV4Src() < addr;
            case greaterThan:
                return t.getV4Src() > addr;
            case lessThanEqual:
                return t.getV4Src() <= addr;
            case greaterThanEqual:
                return t.getV4Src() >= addr;
            default:
                return false;
        }
    }

    std::string toString() override {
        return "ip.src " + std::string(operatorType[op]) + " " + pcpp::IPv4Address(addr).toString();
    }
};

class DstIPFilter : public Filter { //filters for src OR dst ip address
private:
    uint32_t addr;
    Operator op;
public:
    DstIPFilter(uint32_t addr, Operator op) : addr(addr), op(op) {}

    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal:
                return t.getV4Dst() == addr;
            case notEqual:
                return t.getV4Dst() != addr;
            case lessThan:
                return t.getV4Dst() < addr;
            case greaterThan:
                return t.getV4Dst() > addr;
            case lessThanEqual:
                return t.getV4Dst() <= addr;
            case greaterThanEqual:
                return t.getV4Dst() >= addr;
            default:
                return false;
        }
    }

    std::string toString() override {
        return "ip.dst " + std::string(operatorType[op]) + " " + pcpp::IPv4Address(addr).toString();
    }
};

class IPFilter : public Filter { //filters for src OR dst ip address
    uint32_t addr;
    Operator op;
public:
    IPFilter(uint32_t addr, Operator op) : addr(addr), op(op) {}

    bool apply(const IPTuple &t) override {
        return SrcIPFilter{addr, op}.apply(t) || DstIPFilter{addr, op}.apply(t);
    }

    std::string toString() override {
        return "ip.addr " + std::string(operatorType[op]) + " " + pcpp::IPv4Address(addr).toString();
    }
};

class SrcPortFilter : public Filter {
private:
    uint16_t port;
    Operator op;
public:
    SrcPortFilter(uint16_t port, Operator op) : port(port), op(op) {}

    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal:
                return t.getPortSrc() == port;
            case notEqual:
                return t.getPortSrc() != port;
            case lessThan:
                return t.getPortSrc() < port;
            case greaterThan:
                return t.getPortSrc() > port;
            case lessThanEqual:
                return t.getPortSrc() <= port;
            case greaterThanEqual:
                return t.getPortSrc() >= port;
            default:
                return false;
        }
    }

    std::string toString() override {
        return "SrcPortFilter " + std::string(operatorType[op]) + std::to_string(port);
    }
};

class DstPortFilter : public Filter {
private:
    uint16_t port;
    Operator op;
public:
    DstPortFilter(uint16_t port, Operator op) : port(port), op(op) {}

    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal:
                return t.getPortDst() == port;
            case notEqual:
                return t.getPortDst() != port;
            case lessThan:
                return t.getPortDst() < port;
            case greaterThan:
                return t.getPortDst() > port;
            case lessThanEqual:
                return t.getPortDst() <= port;
            case greaterThanEqual:
                return t.getPortDst() >= port;
            default:
                return false;
        }
    }

    std::string toString() override {
        return "DstPortFilter: " + std::string(operatorType[op]) + std::to_string(port);
    }
};

class PortFilter : public Filter { //filters for src OR dst ip address
    uint16_t port;
    Operator op;
public:
    PortFilter(uint16_t port, Operator op) : port(port), op(op) {}

    bool apply(const IPTuple &t) override {
        return SrcPortFilter{port, op}.apply(t) || DstPortFilter{port, op}.apply(t);
    }

    std::string toString() override {
        return "PortFilter";
    }
};

class ProtocolFilter : public Filter {
private:
    uint8_t protocolId;
    Operator op;
public:
    ProtocolFilter(uint8_t protocolId, Operator op) : protocolId(protocolId), op(op) {}

    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal:
                return t.getProtocol() == protocolId;
            case notEqual:
                return t.getProtocol() != protocolId;
            case lessThan:
                return t.getProtocol() < protocolId;
            case greaterThan:
                return t.getProtocol() > protocolId;
            case lessThanEqual:
                return t.getProtocol() <= protocolId;
            case greaterThanEqual:
                return t.getProtocol() >= protocolId;
            default:
                return false;
        }
    }

    std::string toString() override {
        return "proto " + std::string(operatorType[op]) + " " + std::to_string(protocolId);
    }
};

class LengthFilter : public Filter {
private:
    uint16_t length;
    Operator op;
public:
    LengthFilter(uint16_t length, Operator op) : length(length), op(op) {}

    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal:
                return t.getLength() == length;
            case notEqual:
                return t.getLength() != length;
            case lessThan:
                return t.getLength() < length;
            case greaterThan:
                return t.getLength() > length;
            case lessThanEqual:
                return t.getLength() <= length;
            case greaterThanEqual:
                return t.getLength() >= length;
            default:
                return false;
        }
    }

    std::string toString() override {
        return "ProtocolFilter: " + std::string(operatorType[op]) + std::to_string(length);
    }
};

class TimeFilter : public Filter {
private:
    timeval time;
    Operator op;
public:
    TimeFilter(timeval time, Operator op) : time(time), op(op) {}

    bool apply(const IPTuple &t) override {
        switch (op) {
            case equal:
                return t.getTvSec() == static_cast<uint64_t>(time.tv_sec) &&
                       t.getTvUsec() == static_cast<uint64_t>(time.tv_usec);
            case notEqual:
                return t.getTvSec() != static_cast<uint64_t>(time.tv_sec) ||
                       t.getTvUsec() != static_cast<uint64_t>(time.tv_usec);
            case lessThan:
                return t.getTvSec() <= static_cast<uint64_t>(time.tv_sec) &&
                       t.getTvUsec() < static_cast<uint64_t>(time.tv_usec);
            case greaterThan:
                return t.getTvSec() >= static_cast<uint64_t>(time.tv_sec) &&
                       t.getTvUsec() > static_cast<uint64_t>(time.tv_usec);
            case lessThanEqual:
                return t.getTvSec() <= static_cast<uint64_t>(time.tv_sec) &&
                       t.getTvUsec() <= static_cast<uint64_t>(time.tv_usec);
            case greaterThanEqual:
                return t.getTvSec() >= static_cast<uint64_t>(time.tv_sec) &&
                       t.getTvUsec() >= static_cast<uint64_t>(time.tv_usec);
            default:
                return false;
        }
    }

    std::string toString() override {
        return "TimeFilter: " + std::string(operatorType[op]) + std::to_string(time.tv_sec) + " " +
               std::to_string(time.tv_usec);
    }
};

class TimeRangeFilter { //checks if the time range overlaps with queried time range
private:
    uint64_t from;
    uint64_t to;
public:
    TimeRangeFilter() {
        from = 0;
        to = 0;
    }

    void setTimeFrom(uint64_t from) {
        this->from = from;
    }

    void setTimeTo(uint64_t to) {
        this->to = to;
    }

    bool apply(const uint64_t &fromTimeFile,
               const uint64_t &toTimeFile) const { //overlap if at least one of the parameters is between from & to of filter if filter is set (at leas one of from & to is not zero)
        return (from == 0 && to == 0) ||
               (fromTimeFile <= from && from <= toTimeFile) ||
               (fromTimeFile <= to && to <= toTimeFile) ||
               (from <= fromTimeFile && fromTimeFile <= to) ||
               (from <= toTimeFile && toTimeFile <= to);
    }


};

//TODO probably recursive parsing with parentheses would be better
//right now looking for operators first, then identifying the filter types from left to right
//eg ip.addr == 10.0.0.6 || ip.addr == 212.199.202.9 && udp
//too complex grammar
//frame.time <= "Oct 15, 2013 16:00:00"
//frame.len > 300


//TYPES
//frame.time
//frame.len
//proto
//udp
//tcp
//icmp
//ip.src
//ip.dst
//ip.addr

//COMPARISON
// >
// <
// >=
// <=
// ==
// !=

//Value
//depends on type, either an ipaddress in normal format (eg "10.0.0.1")
//for date it must be "Oct 15, 2013 16:00:00"
//else for length, protocol or port is an integer

//language looks like this ([TYPE] [COMPARISON] [VALUE] [LOGICALOP])*

static const std::vector<std::string> filterType = {
        "frame.time", "frame.len", "proto", "ip.src", "ip.dst", "ip.addr"
};


void parseFilter(std::string filterString, AndFilter &filter) {
    std::vector<std::string> commands{};
    std::stringstream ss(filterString);

    std::string s;
    while (std::getline(ss, s, ' ')) {
        commands.push_back(s);
    }

    BoolFilter *boolFilter = &filter;
    for (size_t i = 0; i < commands.size(); ++i) {
        std::string command = commands.at(i);
        std::string comparison = "NULL";
        std::string value = "NULL";

        if (command == "udp") {
            command = "proto";
            comparison = "==";
            value = "17";
        } else if (command == "tcp") {
            command = "proto";
            comparison = "==";
            value = "6";
        } else if (command == "icmp") {
            command = "proto";
            comparison = "==";
            value = "1";
        } else {
            comparison = commands.at(++i);
            value = commands.at(++i);
        }

        std::string nextBoolFilter = "NULL";
        if (i + 1 < commands.size()) { //there is a command next, it must be a boolean filter
            nextBoolFilter = commands.at(++i);
        }

        Operator op = static_cast<Operator>(std::distance(operatorType.begin(),
                                                          std::find(operatorType.begin(), operatorType.end(),
                                                                    comparison)));

        Filter *typeFilter;
        switch (std::distance(filterType.begin(), std::find(filterType.begin(), filterType.end(), command))) {
            case 0:
                //TODO make timeval from string
                typeFilter = new TimeFilter({123, 123}, op);
                break;
            case 1:
                typeFilter = new LengthFilter(std::stoi(value), op);
                break;
            case 2:
                typeFilter = new ProtocolFilter(std::stoi(value), op);
                break;
            case 3:
                typeFilter = new SrcIPFilter(pcpp::IPv4Address(value).toInt(), op);
                break;
            case 4:
                typeFilter = new DstIPFilter(pcpp::IPv4Address(value).toInt(), op);
                break;
            case 5:
                typeFilter = new IPFilter(pcpp::IPv4Address(value).toInt(), op);
                break;
            default:
                assert(false);
        }
        if (nextBoolFilter == "&&") {
            AndFilter *andFilter = new AndFilter();
            andFilter->addFilter(typeFilter);
            boolFilter->addFilter(andFilter);
            boolFilter = andFilter;
        } else if (nextBoolFilter == "||") {
            OrFilter *orFilter = new OrFilter();
            orFilter->addFilter(typeFilter);
            boolFilter->addFilter(orFilter);
            boolFilter = orFilter;
        } else if (nextBoolFilter == "NULL") { //no new filter query must end, add to previous filter
            boolFilter->addFilter(typeFilter);
            break;
        } else {
            assert(false);
        }
    }
}

#endif //IMPLEMENTATION_FILTER_H
