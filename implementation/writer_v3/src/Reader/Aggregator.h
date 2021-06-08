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

    enum IpTupleField {
        v4Src,
        v4Dst,
        portSrc,
        portDst,
        protocol,
        length
    };

    class Aggregator {
    private:
        tsl::robin_map<uint64_t, std::vector<uint32_t>> map{};
        AggregationOperator op;
        IpTupleField field;
        uint32_t interval; //interval in microseconds

    public:
        Aggregator() = delete;

        Aggregator(const Aggregator &) = delete;

        Aggregator &operator=(const Aggregator &) = delete;

        Aggregator(AggregationOperator op, IpTupleField field, uint32_t interval) : op(op), field(field),
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

        std::vector<uint32_t> calculate() {
            std::vector<uint32_t> ret{};
            ret.reserve(map.size());

           std::function<uint32_t(const std::vector<uint32_t> &vec)> agg;
            switch (this->op) {
                case sum:
                    agg = [](const std::vector<uint32_t> &vec){return std::accumulate(vec.begin(), vec.end(), 0);};
                    break;
                case mean: break;
                case min: break;
                case max: break;
                case count: break;
                case count_dist: break;
            }

            for (const auto &entry : map) {
                ret.emplace_back(agg(entry.second));
            }

            return ret;
        }
    };
}

#endif //IMPLEMENTATION_AGGREGATOR_H
