//
// Created by ubuntu on 09.06.21.
//

#ifndef IMPLEMENTATION_AGGREGATIONTHREAD_H
#define IMPLEMENTATION_AGGREGATIONTHREAD_H

#include "../Aggregator.h"
#include "../../Common/ConcurrentQueue/concurrentqueue.h"

namespace reader {
    namespace threadOperations {
        void aggregates(reader::AggregationOperator op, reader::IpTupleField field, uint64_t interval,
                        moodycamel::ConcurrentQueue<common::IPTuple> &inQueue,
                        std::atomic<bool> &filterIpTuplesFinished) {
            reader::Aggregator agg(op, field, interval);
            while (!filterIpTuplesFinished || inQueue.size_approx() != 0) {
                std::vector<common::IPTuple> temp{1000};
                size_t dequeued = inQueue.try_dequeue_bulk(temp.begin(), 1000);
                for (size_t i = 0; i < dequeued; ++i) {
                    agg.add(temp.at(i));
                }
            }
            auto x = agg.calculate();

            //todo write csv
            std::cout << "size: " << x.size() << std::endl;
            for (const auto &temp : x) {
                std::cout << temp.first << " " << temp.second << std::endl;
            }

        }
    }
}
#endif //IMPLEMENTATION_AGGREGATIONTHREAD_H
