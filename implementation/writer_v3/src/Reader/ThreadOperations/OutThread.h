//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_OUTTHREAD_H
#define IMPLEMENTATION_OUTTHREAD_H

#include <iomanip>
#include "../../Common/IPTuple.h"


namespace reader {
    namespace threadOperations {
        void writeOut(std::ostream &os, moodycamel::ConcurrentQueue <common::IPTuple> &inQueue,
                      std::atomic<bool> &filterIpTuplesFinished) {

            const int ipWidth = 25;
            os << std::left << std::setw(ipWidth) << "src IP (: port)"
               << std::setw(ipWidth) << "dst IP (: port)  "
               << std::setw(10) << "protocol"
               << std::setw(8) << "length"
               << std::setw(15) << "sec"
               << std::setw(15) << "usec" << '\n';


            while (!filterIpTuplesFinished || inQueue.size_approx() != 0) {
                std::vector<common::IPTuple> temp{1000};
                size_t dequeued = inQueue.try_dequeue_bulk(temp.begin(), 1000);

                ///sorting by time in batches for some continuity
                std::sort(temp.begin(), temp.begin() + dequeued,
                          [](const common::IPTuple &a, const common::IPTuple &b) -> bool {
                              return (a.getTvSec() < b.getTvSec()) ||
                                     (a.getTvSec() == b.getTvSec() && a.getTvUsec() < b.getTvUsec());
                          });

                for (size_t i = 0; i < dequeued; ++i) {
                    const common::IPTuple &t = *(temp.begin() + i);
                    if(t.getProtocol() == TCPn || t.getProtocol() == UDPn){ ///in case the protocol has port print also port
                        os << std::setw(ipWidth) << pcpp::IPv4Address(t.getV4Src()).toString() + ":" + std::to_string(t.getPortSrc())
                           << std::setw(ipWidth) << pcpp::IPv4Address(t.getV4Dst()).toString() + ":" + std::to_string(t.getPortDst())
                           << std::setw(10) << std::to_string(t.getProtocol())
                           << std::setw(8) << std::to_string(t.getLength())
                           << std::setw(15) << t.getTvSec()
                           << std::setw(15) << t.getTvUsec() << '\n';
                    } else {
                        os << std::setw(ipWidth) << pcpp::IPv4Address(t.getV4Src()).toString()
                           << std::setw(ipWidth) << pcpp::IPv4Address(t.getV4Dst()).toString()
                           << std::setw(10) << std::to_string(t.getProtocol())
                           << std::setw(8) << std::to_string(t.getLength())
                           << std::setw(15) << t.getTvSec()
                           << std::setw(15) << t.getTvUsec() << '\n';
                    }
                }
            }
        }
    }
}

#endif //IMPLEMENTATION_OUTTHREAD_H
