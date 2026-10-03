#ifndef PACKET_MONITOR_HPP
#define PACKET_MONITOR_HPP

#include <string>

#include "connection_tracker.hpp"
#include "detector.hpp"

class PacketMonitor {
public:
    PacketMonitor(
        const std::string& interface,
        ConnectionTracker& tracker,
        Detector& detector
    );

    void start();

private:
    std::string interfaceName;

    ConnectionTracker& connectionTracker;
    Detector& detector;

    void processPacket(
        const unsigned char* packet,
        unsigned int length
    );
};

#endif
