#include <iostream>
#include <vector>

#include "packet_monitor.hpp"
#include "connection_tracker.hpp"
#include "detector.hpp"
#include "database.hpp"
#include "firewall_manager.hpp"
#include "config_manager.hpp"


int main() {

    ConfigManager config(
        "config/nids.json"
    );


    if (!config.load()) {

        std::cerr
            << "[MAIN] Configuration loading failed."
            << std::endl;

        return 1;
    }


    const std::string interfaceName =
        config.getInterface();


    const int scanThreshold =
        config.getScanThreshold();


    const int scanWindowSeconds =
        config.getScanWindowSeconds();


    const int connectionThreshold =
        config.getConnectionThreshold();


    const int connectionWindowSeconds =
        config.getConnectionWindowSeconds();


    const bool autoBlock =
        config.getAutoBlock();


    const int blockDurationSeconds =
        config.getBlockDurationSeconds();


    const std::string databasePath =
        config.getDatabasePath();


    const std::vector<int> suspiciousPorts =
        config.getSuspiciousPorts();


    ConnectionTracker connectionTracker;


    Database database(
        databasePath
    );


    if (!database.initialize()) {

        std::cerr
            << "[MAIN] Database initialization failed."
            << std::endl;

        return 1;
    }


    FirewallManager firewallManager;


    Detector detector(
        scanThreshold,
        scanWindowSeconds,
        connectionThreshold,
        connectionWindowSeconds,
        database,
        firewallManager,
        autoBlock,
        blockDurationSeconds,
        suspiciousPorts
    );


    std::cout
        << std::endl
        << "========================================"
        << std::endl
        << "       EMBEDDED LINUX NIDS"
        << std::endl
        << "========================================"
        << std::endl;


    std::cout
        << "Interface          : "
        << interfaceName
        << std::endl;


    std::cout
        << "Database           : "
        << databasePath
        << std::endl;


    std::cout
        << "Scan Rule          : "
        << scanThreshold
        << " unique ports / "
        << scanWindowSeconds
        << " seconds"
        << std::endl;


    std::cout
        << "Connection Rule    : "
        << connectionThreshold
        << " connections / "
        << connectionWindowSeconds
        << " seconds"
        << std::endl;


    std::cout
        << "Suspicious Ports   : ";


    for (size_t i = 0;
         i < suspiciousPorts.size();
         ++i) {

        std::cout
            << suspiciousPorts[i];


        if (i + 1 <
            suspiciousPorts.size()) {

            std::cout
                << ", ";
        }
    }


    std::cout
        << std::endl;


    std::cout
        << "Auto Block         : "
        << (autoBlock ? "ENABLED" : "DISABLED")
        << std::endl;


    std::cout
        << "Block Duration     : "
        << blockDurationSeconds
        << " seconds"
        << std::endl;


    std::cout
        << "========================================"
        << std::endl;


    PacketMonitor monitor(
        interfaceName,
        connectionTracker,
        detector
    );


    monitor.start();


    return 0;
}
