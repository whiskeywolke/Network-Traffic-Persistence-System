//
// Created by ubuntu on 08.06.21.
//

#ifndef IMPLEMENTATION_PCAPWRITERTHREAD_H
#define IMPLEMENTATION_PCAPWRITERTHREAD_H

#include <pcap/pcap.h>
#include "../Converter.h"


namespace reader {
    namespace threadOperations {
        void writeToPcapFile(const std::string filePath, const std::string fileName,
                             moodycamel::ConcurrentQueue<common::IPTuple> &inQueue,
                             std::atomic<bool> &filterIpTuplesFinished) {

            pcap_t *handle = pcap_open_dead(DLT_RAW,
                                            1
                                                    << 16); //second parameter is snapshot length, not relevant as set by caplen
            std::string completeName = (filePath + fileName);
            pcap_dumper_t *dumper = pcap_dump_open(handle, completeName.c_str());

            while (!filterIpTuplesFinished || inQueue.size_approx() != 0) {
                common::IPTuple t;

                if (inQueue.try_dequeue(t)) {
                    if (t.getProtocol() == TCPn) {
                        unsigned char tcpPacket[MINTCPHEADERLENGTH] = {0x00};
                        makeTcpPacket(t, tcpPacket);

                        struct pcap_pkthdr pcap_hdr{};
                        pcap_hdr.caplen = MINTCPHEADERLENGTH; //captured length
                        pcap_hdr.len = t.getLength();// >= MINTCPPKTLENGTH ? t.getLength() : MINTCPPKTLENGTH;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
                        pcap_hdr.ts.tv_sec = t.getTvSec();
                        pcap_hdr.ts.tv_usec = t.getTvUsec();

                        pcap_dump((u_char *) dumper, &pcap_hdr, tcpPacket);
                    } else if (t.getProtocol() == UDPn) {
                        unsigned char udpPacket[MINUDPHEADERLENGTH] = {0x00};
                        makeUdpPacket(t, udpPacket);

                        struct pcap_pkthdr pcap_hdr{};
                        pcap_hdr.caplen = MINUDPHEADERLENGTH; //captured length
                        pcap_hdr.len = t.getLength();//MINUDPPKTLENGTH;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
                        pcap_hdr.ts.tv_sec = t.getTvSec();
                        pcap_hdr.ts.tv_usec = t.getTvUsec();

                        pcap_dump((u_char *) dumper, &pcap_hdr, udpPacket);
                    } else if (t.getProtocol() == ICMPn) {
                        unsigned char icmpPacket[MINICMPHEADERLENGTH] = {0x00};
                        makeIcmpPacket(t, icmpPacket);

                        struct pcap_pkthdr pcap_hdr{};
                        pcap_hdr.caplen = MINICMPHEADERLENGTH; //captured length
                        pcap_hdr.len = t.getLength();//MINICMPPKTLENGTH;            //actual length of packet (>=caplen) in bytes //for imcp must be >= 21 to prevent misrepresentation
                        pcap_hdr.ts.tv_sec = t.getTvSec();
                        pcap_hdr.ts.tv_usec = t.getTvUsec();

                        pcap_dump((u_char *) dumper, &pcap_hdr, icmpPacket);
                    } else {
                        assert(false);
                    }
                }
            }
            pcap_dump_close(dumper);
        }
    }
}
#endif //IMPLEMENTATION_PCAPWRITERTHREAD_H
