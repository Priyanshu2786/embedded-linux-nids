#ifndef DETECTOR_HPP
#define DETECTOR_HPP

#include "connection_tracker.hpp"
#include "database.hpp"
#include "firewall_manager.hpp"
#include "risk_engine.hpp"
#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>


struct PortScanRecord {

    std::chrono::system_clock::time_point timestamp;

    std::string destinationIP;

    uint16_t destinationPort;
};


class Detector {

public:

    Detector(
        int scanThreshold,
        int scanWindowSeconds,
        int connectionThreshold,
        int connectionWindowSeconds,
        Database& database,
        FirewallManager& firewallManager,
        bool autoBlock,
        int blockDurationSeconds,
        const std::vector<int>& suspiciousPorts
    );

    void analyze(
        const ConnectionEvent& event
    );


private:

    int scanThreshold;

    int scanWindowSeconds;

    int connectionThreshold;

    int connectionWindowSeconds;

    Database& database;

    FirewallManager& firewallManager;

    bool autoBlock;

    int blockDurationSeconds;

    std::vector<int> suspiciousPorts;


    std::map<
        std::string,
        std::vector<PortScanRecord>
    > scanHistory;


    std::map<
        std::string,
        std::chrono::system_clock::time_point
    > lastAlertTime;


    std::map<
        std::string,
        std::chrono::system_clock::time_point
    > lastSuspiciousPortAlertTime;


    std::map<
        std::string,
        std::vector<
            std::chrono::system_clock::time_point
        >
    > connectionHistory;


    std::map<
        std::string,
        std::chrono::system_clock::time_point
    > lastConnectionRateAlertTime;


    void detectPortScan(
        const ConnectionEvent& event
    );


    void detectSuspiciousPort(
        const ConnectionEvent& event
    );


    void detectConnectionRate(
        const ConnectionEvent& event
    );


    void cleanup(
        const std::string& sourceIP
    );


    void cleanupConnectionHistory(
        const std::string& sourceIP
    );


    bool isSuspiciousPort(
        uint16_t port
    ) const;


    std::string makeAlertKey(
        const std::string& sourceIP,
        const std::string& destinationIP
    ) const;
};

#endif
