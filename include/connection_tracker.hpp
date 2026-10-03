#ifndef CONNECTION_TRACKER_HPP
#define CONNECTION_TRACKER_HPP

#include <string>
#include <cstdint>
#include <chrono>
#include <vector>

struct ConnectionEvent {
    std::string sourceIP;
    std::string destinationIP;

    uint16_t sourcePort;
    uint16_t destinationPort;

    std::string protocol;

    std::chrono::system_clock::time_point timestamp;
};

class ConnectionTracker {
public:
    void addConnection(const ConnectionEvent& event);

    std::vector<ConnectionEvent> getRecentConnections(
        const std::string& sourceIP,
        int windowSeconds
    );

    size_t totalConnections() const;

private:
    std::vector<ConnectionEvent> connections;

    void cleanup();
};

#endif
