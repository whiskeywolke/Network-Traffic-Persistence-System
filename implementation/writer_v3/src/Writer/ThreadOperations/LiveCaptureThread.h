//
// Created by ubuntu on 14.06.21.
//

#ifndef IMPLEMENTATION_LIVECAPTURETHREAD_H
#define IMPLEMENTATION_LIVECAPTURETHREAD_H

#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <csignal>

namespace writer {
    namespace threadOperations {

        bool shutdownLiveReader = false;

        void handleSignal(int signal) {
            if (signal == 2) {
                std::cout << "\nShutting down\n";
                shutdownLiveReader = true;
            }
        }

        static void handlePacketArrival(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *queue) {
            auto *queueRaw = (moodycamel::ConcurrentQueue<pcpp::RawPacket> *) queue;
            pcpp::Packet parsedPacket(packet);
            queueRaw->enqueue(*packet);
        }

        void readLiveDevice(const std::string &deviceName, std::vector<bool> *status, int threadID,
                            moodycamel::ConcurrentQueue<pcpp::RawPacket> *outQueue, std::mutex &status_mutex,
                            std::atomic<bool> &readingFinished, std::atomic<long> &readingDuration,
                            std::atomic<long> &readPackets) {


            ///check if device exists otherwise exit
            std::vector<pcpp::PcapLiveDevice *> devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
            bool deviceExists = false;
            for (const auto dev : devices) {
                if (dev->getName() == deviceName)
                    deviceExists = true;
            }
            if (!deviceExists) {
                std::cout << "Cannot find device with name: " << deviceName << "\nexiting\n";
                exit(1);
            }

            pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(deviceName);
            if (!dev->open()) {
                std::cout << "Could not open device, do you have the rights to capture from net device?" << std::endl;
                exit(1);
            }
            std::cout << "Ctrl + C to shut down program\n";
            auto start = std::chrono::high_resolution_clock::now();
            ///setting filter to only capture ipv4, tcp udp icmp
            dev->setFilter(getPredefinedFilterAsString());
            ///starting capture in different thread
            dev->startCapture(handlePacketArrival, outQueue);

            ///wait for stop signal
            signal(SIGINT, handleSignal);
            while (!shutdownLiveReader) {
                sleep(1.5);
            }

            ///stop device
            dev->stopCapture();

            /// shutdownLiveReader procedure
            {
                std::lock_guard<std::mutex> lock(status_mutex);
                status->at(threadID) = true;
                if (std::find(status->begin(), status->end(), false) ==
                    status->end()) {  //false cannot be found -> all other threads are finished
                    readingFinished = true;
                }
            }
            auto end = std::chrono::high_resolution_clock::now();
            readingDuration += std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            pcap_stat stats{};
            dev->getStatistics(stats);
            readPackets += stats.ps_recv;
            if (readPackets == 0) {
                ++readPackets; //to prevent floating point exception during statistics calculation
            }
            dev->close();
        }
    }
}

#endif //IMPLEMENTATION_LIVECAPTURETHREAD_H
