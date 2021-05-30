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
namespace filter {
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
            if (filters.empty()) {
                return true;
            }
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
            return "length " + std::string(operatorType[op]) + " " + std::to_string(length);
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
            return "frame.time: " + std::string(operatorType[op]) + " " + std::to_string(time.tv_sec) + " " +
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

        std::string toString() {
            return "from: " + std::to_string(from) + " to: " + std::to_string(to);
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

//expects a string like this: Oct 15, 2013 16:00:00" and converts it to timeval, microseconds are set to 0
    struct timeval stringToTimeval(std::string timeString) {
        std::string month = timeString.substr(0, 3); //must be month
        if (month == "Jan" || month == "jan") {
            timeString.erase(0, 1);
            timeString.at(0) = '0';
            timeString.at(1) = '1';
        } else if (month == "Feb" || month == "feb") {
            timeString.erase(0, 1);
            timeString.at(0) = '0';
            timeString.at(1) = '2';
        } else if (month == "Mar" || month == "mar") {
            timeString.erase(0, 1);
            timeString.at(0) = '0';
            timeString.at(1) = '2';
        } else if (month == "Apr" || month == "apr") {
            timeString.erase(0, 1);
            timeString.at(0) = '0';
            timeString.at(1) = '4';
        } else if (month == "May" || month == "may") {
            timeString.erase(0, 1);
            timeString.at(0) = '0';
            timeString.at(1) = '5';
        } else if (month == "Jun" || month == "jun") {
            timeString.erase(0, 1);
            timeString.at(0) = '0';
            timeString.at(1) = '6';
        } else if (month == "Jul" || month == "jul") {
            timeString.erase(0, 1);
            timeString.at(0) = '0';
            timeString.at(1) = '7';
        } else if (month == "Aug" || month == "aug") {
            timeString.erase(0, 1);
            timeString.at(0) = '0';
            timeString.at(1) = '8';
        } else if (month == "Sep" || month == "sep") {
            timeString.erase(0, 1);
            timeString.at(0) = '0';
            timeString.at(1) = '9';
        } else if (month == "Oct" || month == "oct") {
            timeString.erase(0, 1);
            timeString.at(0) = '1';
            timeString.at(1) = '0';
        } else if (month == "Nov" || month == "nov") {
            timeString.erase(0, 1);
            timeString.at(0) = '1';
            timeString.at(1) = '1';
        } else if (month == "Dec" || month == "dec") {
            timeString.erase(0, 1);
            timeString.at(0) = '1';
            timeString.at(1) = '2';
        } else {
            std::cout << "INVALID MONTH" << std::endl;
        }

        static const std::string dateTimeFormat{"%m %d, %Y %H:%M:%S"};
        struct tm timestamp{};

        strptime(timeString.c_str(), dateTimeFormat.c_str(), &timestamp);

        //find out if Daylight saving time is active
        std::time_t tTemp = std::time(0);
        std::tm *now = std::localtime(&tTemp);

        timestamp.tm_isdst = now->tm_isdst;
        time_t t = mktime(&timestamp);

        //query resolution not higher than seconds
        timeval myTimeval{};
        myTimeval.tv_sec = t;
        myTimeval.tv_usec = 0;

        return myTimeval;
    }

    std::vector<std::string> reverseCommandVector(const std::vector<std::string> &input) {
        std::vector<std::string> ret{};
        ret.reserve(input.size());

        for (size_t i = (input.size()); i > 0; --i) {
            if (input.at(i - 1) == "&&" || input.at(i - 1) == "||" || input.at(i - 1) == "udp" ||
                input.at(i - 1) == "tcp" || input.at(i - 1) == "icmp") {
                ret.emplace_back(input.at(i - 1));
            } else {
                ret.emplace_back(input.at(i - 3));
                ret.emplace_back(input.at(i - 2));
                ret.emplace_back(input.at(i - 1));
                i -= 2;
            }
        }
        assert(input.size() == ret.size());
        return ret;
    }

    std::vector<std::string> prepareCommands(const std::string &filterString) {
        std::vector<std::string> commands{};
        std::stringstream ss(filterString);

        std::string s;
        while (std::getline(ss, s, ' ')) {
            if (!s.empty()) {
                commands.push_back(s);
            }
        }
        //iterate over commands vector and merge time parameters if set,
        // remove any empty entries
        // remove space symbol at the begin and at the end of a commmand
        // resolve shortcuts like udp tcp icmp
        for (size_t i = 0; i < commands.size(); ++i) {
            std::string tempCommand = commands.at(i);
            std::transform(tempCommand.begin(), tempCommand.end(), tempCommand.begin(), ::tolower);
            if (tempCommand == "udp") {
                commands.at(i) = "proto";
                commands.insert(commands.begin() + i + 1, "==");
                commands.insert(commands.begin() + i + 2, "17");
                i += 2;
            } else if (tempCommand == "tcp") {
                commands.at(i) = "proto";
                commands.insert(commands.begin() + i + 1, "==");
                commands.insert(commands.begin() + i + 2, "6");
                i += 2;
            } else if (tempCommand == "icmp") {
                commands.at(i) = "proto";
                commands.insert(commands.begin() + i + 1, "==");
                commands.insert(commands.begin() + i + 2, "1");
                i += 2;
            } else if (commands.at(i) == filterType.at(0)) { // frame.time == "Oct 15, 2013 16:00:00"
                commands.at(i + 2) += " " + commands.at(i + 3) + " " + commands.at(i + 4) + " " + commands.at(i + 5);
                commands.erase(commands.begin() + i + 3, commands.begin() + i + 6);
            }
        }
        return commands;
    }

    uint64_t getMaxTime(const std::string &filterString) {
        std::vector<std::string> commands = prepareCommands(filterString);
        uint64_t maxTime = 0;
        for (size_t i = 0; i < commands.size(); ++i) {
            if (commands.at(i) == "frame.time") {
                struct timeval t = stringToTimeval(commands.at(i + 2));
                uint64_t temp = t.tv_sec * 1000000 + t.tv_usec;
                if (temp > maxTime) {
                    maxTime = temp;
                }
            }
        }
        return maxTime;
    }

    TimeRangeFilter makeTimerangeFilter(const std::string &filterString) {
        TimeRangeFilter ret{};

        std::vector<std::string> commands = prepareCommands(filterString);
        uint64_t maxTime = 0;
        Operator maxOperator = Operator::lessThanEqual;
        bool maxFound = false;
        uint64_t minTime = std::numeric_limits<uint64_t>::max();
        Operator minOperator = Operator::greaterThanEqual;
        bool minFound = false;

        bool timeIsIrrelevant = false;

        for (size_t i = 0; i < commands.size(); ++i) {
            //in case a known command that is not frame.time before or after the time is linked with "or"
            // everything needs to be searched e.g. (udp || time.frame > 5) or e.g. (time.frame > 5 || udp) means that all UDP packets are wanted and all other packets with a timestamp greater than 5
            //in this case all files need to be searched


            if (std::find(filterType.begin(), filterType.end(), commands.at(i)) != filterType.end() &&
                commands.at(i) != "frame.time" && (commands.size() > i + 3 && commands.at(i + 3) == "||")) {
                timeIsIrrelevant = true;
                break;
            } else if (commands.at(i) == "frame.time") {
                // if after a frame.time an "or" follows which is not frame.time, time is also irrelevant
                if (commands.size() > i + 4 && commands.at(i + 4) != "frame.time" && commands.at(i + 3) == "||") {
                    timeIsIrrelevant = true;
                    break;
                }

                struct timeval t = stringToTimeval(commands.at(i + 2));
                uint64_t temp = t.tv_sec * 1000000 + t.tv_usec;
                Operator op = static_cast<Operator>(std::distance(operatorType.begin(),
                                                                  std::find(operatorType.begin(),
                                                                            operatorType.end(),
                                                                            commands.at(i + 1))));
                if (temp > maxTime && (op == Operator::lessThanEqual || op == Operator::lessThan ||
                                       op == Operator::equal)) { //can only be a max value if operator is < or <= or ==
                    maxTime = temp;
                    maxOperator = op;
                    maxFound = true;
                }
                if (temp < minTime && (op == Operator::greaterThanEqual || op == Operator::greaterThan || op ==
                                                                                                          Operator::equal)) { //can only be a min value if operator is > or >= or ==) {
                    minTime = temp;
                    minOperator = op;
                    minFound = true;
                }
            }
        }

        if (timeIsIrrelevant) {
            ret.setTimeFrom(0);
            ret.setTimeTo(std::numeric_limits<uint64_t>::max());
            std::cout << "Time is irrelevant for file pruning, searching all files" << std::endl;
        } else {
            if (!maxFound) {
                maxTime = std::numeric_limits<uint64_t>::max();
                maxFound = true;
            }
            if (!minFound) {
                minTime = 0;
                minFound = true;
            }

            //in case the range is specified between to values
            if (minTime < maxTime) {
                ret.setTimeFrom(minTime);
                ret.setTimeTo(maxTime);
            } else if (minTime == maxTime) {
                //so if min & max are equal assume that
                ret.setTimeFrom(minTime);
                ret.setTimeTo(maxTime);
            } else if (maxTime == 0 && minTime == std::numeric_limits<uint64_t>::max()) {
                //no time was found, do nothing
            } else {
                std::cout << "max: " << maxTime << std::endl;
                std::cout << "min: " << minTime << std::endl;
                std::cout << "maxop: " << maxOperator << std::endl;
                std::cout << "minop: " << minOperator << std::endl;
                std::cout << ">=: " << Operator::greaterThanEqual << std::endl;
                std::cout << "this time search is not implemented!" << std::endl;
                assert(false);
            }
        }
        return ret;
    }

    void parseFilter(const std::string &filterString, AndFilter &filter) {
        std::vector<std::string> commands = prepareCommands(filterString);
        //commands = reverseCommandVector(commands);     //reverse vector to make it a left to right binding query language (does it make sense?)

        BoolFilter *boolFilter = &filter;
        for (size_t i = 0; i < commands.size(); ++i) {
            std::string command = commands.at(i);
            std::string comparison = commands.at(++i);
            std::string value = commands.at(++i);
            std::string nextBoolFilter = "NULL";

            if (i + 1 < commands.size()) { //there is a command next, it must be a boolean filter
                nextBoolFilter = commands.at(++i);
            }

            Operator op = static_cast<Operator>(std::distance(operatorType.begin(),
                                                              std::find(operatorType.begin(), operatorType.end(),
                                                                        comparison)));

            Filter *typeFilter;
            switch (std::distance(filterType.begin(), std::find(filterType.begin(), filterType.end(), command))) {
                case 0: {
                    struct timeval t = stringToTimeval(value);
                    typeFilter = new TimeFilter({t.tv_sec, t.tv_usec}, op);
                    break;
                }
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
                    std::cout << "error at: " << command << std::endl;
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
                std::cout << "nextBoolFilter is: " << nextBoolFilter << std::endl;
                assert(false);
            }
        }
    }

}
#endif //IMPLEMENTATION_FILTER_H