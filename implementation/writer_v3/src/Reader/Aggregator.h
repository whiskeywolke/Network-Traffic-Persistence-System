//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_AGGREGATOR_H
#define IMPLEMENTATION_AGGREGATOR_H

#include "../Common/HashMap/robin_map.h"
#include "../Common/IPTuple.h"
#include <vector>
#include <numeric>

namespace reader {
    enum AggregationOperator {
        sum,
        mean,
        min,
        max,
        count,
        count_dist
    };
    static const std::vector<std::string> AggregationOperatorStrings = {
            "sum", "mean", "min", "max", "count", "count_dist"
    };
    enum IpTupleField {
        v4Src,
        v4Dst,
        portSrc,
        portDst,
        protocol,
        length
    };
    static const std::vector<std::string> IpTupleFieldStrings = {
            "v4Src", "v4Dst", "portSrc", "portDst", "protocol", "length"
    };

    class Aggregator {
    private:
        tsl::robin_map<uint64_t, std::vector<uint32_t>> map{};
        AggregationOperator op;
        IpTupleField field;
        uint64_t interval; //interval in microseconds

    public:
        Aggregator() = delete;

        Aggregator(const Aggregator &) = delete;

        Aggregator &operator=(const Aggregator &) = delete;

        Aggregator(AggregationOperator op, IpTupleField field, uint64_t interval) : op(op), field(field),
                                                                                    interval(interval) {}

        void add(const common::IPTuple &ipTuple) {
            u_int64_t timeslot = (ipTuple.getTvSec() * 1000000 + ipTuple.getTvUsec()) / interval;
            uint32_t value{};

            switch (field) {
                case v4Src :
                    value = ipTuple.getV4Src();
                    break;
                case v4Dst :
                    value = ipTuple.getV4Dst();
                    break;
                case portSrc :
                    value = ipTuple.getPortSrc();
                    break;
                case portDst :
                    value = ipTuple.getPortDst();
                    break;
                case protocol:
                    value = ipTuple.getProtocol();
                    break;
                case length :
                    value = ipTuple.getLength();
                    break;
            }

            if (map.find(timeslot) != map.end()) {
                map.at(timeslot).emplace_back(value);
            } else {
                auto newEntry = std::pair<u_int64_t, std::vector<uint32_t>>(timeslot, std::vector<uint32_t>{});
                newEntry.second.reserve(1000); //reserve space for faster inserts later
                newEntry.second.emplace_back(value);
                map.insert(newEntry);
            }
        };

        tsl::robin_map<uint64_t, uint32_t> calculate() {
            tsl::robin_map<uint64_t, uint32_t> ret{};
            ret.reserve(map.size());

            std::function<uint32_t(const std::vector<uint32_t> &vec)> agg;
            switch (this->op) {
                case sum:
                    agg = [](const std::vector<uint32_t> &vec) { return std::accumulate(vec.begin(), vec.end(), 0); };
                    break;
                case mean:
                    agg = [](const std::vector<uint32_t> &vec) {
                        return std::accumulate(vec.begin(), vec.end(), 0) / vec.size();
                    };
                    break;
                case min:
                    agg = [](const std::vector<uint32_t> &vec) { return *std::min_element(vec.begin(), vec.end()); };
                    break;
                case max:
                    agg = [](const std::vector<uint32_t> &vec) { return *std::max_element(vec.begin(), vec.end()); };
                    break;
                case count:
                    agg = [](const std::vector<uint32_t> &vec) { return vec.size(); };
                    break;
                case count_dist:
                    agg = [](const std::vector<uint32_t> &vec) {
                        auto temp = vec; //todo prevent copy
                        std::sort(temp.begin(), temp.end());
                        auto it = std::unique(temp.begin(), temp.end());
                        return it - temp.begin();
                    };
                    break;
            }

            for (const auto &entry : map) {
                auto newEntry = std::pair<uint64_t, uint32_t>(entry.first * interval, agg(entry.second));
                ret.insert(newEntry);
            }

            return ret;
        }
    };
}

#endif //IMPLEMENTATION_AGGREGATOR_H
