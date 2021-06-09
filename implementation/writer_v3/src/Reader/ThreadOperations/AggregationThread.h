//
// Created by ubuntu on 09.06.21.
//

#ifndef IMPLEMENTATION_AGGREGATIONTHREAD_H
#define IMPLEMENTATION_AGGREGATIONTHREAD_H

#include "../Aggregator.h"
#include "../../Common/ConcurrentQueue/concurrentqueue.h"

namespace reader {
    namespace threadOperations {
        void aggregate(std::string filename, reader::AggregationOperator op, reader::IpTupleField field, uint64_t interval,
                       moodycamel::ConcurrentQueue<common::IPTuple> &inQueue,
                       std::atomic<bool> &filterIpTuplesFinished) {
            ///creating aggregator object
            reader::Aggregator agg(op, field, interval);
            ///aggregating until queue is empty and previous steps are finished
            while (!filterIpTuplesFinished || inQueue.size_approx() != 0) {
                std::vector<common::IPTuple> temp{1000};
                size_t dequeued = inQueue.try_dequeue_bulk(temp.begin(), 1000);
                for (size_t i = 0; i < dequeued; ++i) {
                    agg.add(temp.at(i));
                }
            }
            auto reduced = agg.calculate();

            ///could hurt performance since single threaded sorting for huge vectors can be slow, since keys in the map are not sorted
            std::vector<std::pair<uint64_t, uint32_t>> sorted{};
            sorted.reserve(reduced.size());
            for(const auto &temp : reduced){
                sorted.emplace_back(temp);
            }
            std::sort(sorted.begin(),sorted.end(),[](const std::pair<uint64_t, uint32_t>&a, const std::pair<uint64_t, uint32_t>&b)->bool{
                return a.first<b.first;
            });

            //todo csv file name & path, combined from query & aggregation
            ///writing csv file
            filename += "_" + AggregationOperatorStrings.at(op);
            filename += "_" + IpTupleFieldStrings.at(field);
            filename += "_" + std::to_string((interval*1.0)/1000000.0) + "secs.csv";
            std::ofstream file(filename);
            file <<"interval"<<","<<AggregationOperatorStrings.at(op)<<"_"<<IpTupleFieldStrings.at(field)<<'\n';
            for (const auto &temp : sorted) {
                file << temp.first <<','<<temp.second<<'\n';
            }
            file.close();
        }
    }
}
#endif //IMPLEMENTATION_AGGREGATIONTHREAD_H
