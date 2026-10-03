#include "config_manager.hpp"

#include <fstream>
#include <iostream>

#include <nlohmann/json.hpp>

using json = nlohmann::json;


ConfigManager::ConfigManager(
    const std::string& configPath
)
    : configPath(configPath),
      interfaceName("enp0s8"),
      scanThreshold(10),
      scanWindowSeconds(5),
      connectionThreshold(100),
      connectionWindowSeconds(10),
      trafficThresholdPPS(1000),
      autoBlock(true),
      blockDurationSeconds(60) {
}


bool ConfigManager::load() {

    std::ifstream file(
        configPath
    );

    if (!file.is_open()) {

        std::cerr
            << "[CONFIG] Failed to open: "
            << configPath
            << std::endl;

        return false;
    }

    try {

        json config;

        file >> config;


        if (config.contains("interface")) {

            interfaceName =
                config["interface"].get<std::string>();
        }


        if (config.contains("scan_threshold")) {

            scanThreshold =
                config["scan_threshold"].get<int>();
        }


        if (config.contains("scan_window_seconds")) {

            scanWindowSeconds =
                config["scan_window_seconds"].get<int>();
        }


        if (config.contains("connection_threshold")) {

            connectionThreshold =
                config["connection_threshold"].get<int>();
        }


        if (config.contains("connection_window_seconds")) {

            connectionWindowSeconds =
                config["connection_window_seconds"].get<int>();
        }


        if (config.contains("traffic_threshold_pps")) {

            trafficThresholdPPS =
                config["traffic_threshold_pps"].get<int>();
        }


        if (config.contains("suspicious_ports")) {

            suspiciousPorts =
                config["suspicious_ports"]
                    .get<std::vector<int>>();
        }


        if (config.contains("auto_block")) {

            autoBlock =
                config["auto_block"].get<bool>();
        }


        if (config.contains("block_duration_seconds")) {

            blockDurationSeconds =
                config["block_duration_seconds"].get<int>();
        }


        if (config.contains("database")) {

            databasePath =
                config["database"].get<std::string>();
        }


        if (config.contains("log_file")) {

            logFile =
                config["log_file"].get<std::string>();
        }


        std::cout
            << "[CONFIG] Configuration loaded successfully."
            << std::endl;

        return true;
    }

    catch (const std::exception& exception) {

        std::cerr
            << "[CONFIG] Error parsing configuration: "
            << exception.what()
            << std::endl;

        return false;
    }
}


std::string ConfigManager::getInterface() const {

    return interfaceName;
}


int ConfigManager::getScanThreshold() const {

    return scanThreshold;
}


int ConfigManager::getScanWindowSeconds() const {

    return scanWindowSeconds;
}


int ConfigManager::getConnectionThreshold() const {

    return connectionThreshold;
}


int ConfigManager::getConnectionWindowSeconds() const {

    return connectionWindowSeconds;
}


int ConfigManager::getTrafficThresholdPPS() const {

    return trafficThresholdPPS;
}


std::vector<int>
ConfigManager::getSuspiciousPorts() const {

    return suspiciousPorts;
}


bool ConfigManager::getAutoBlock() const {

    return autoBlock;
}


int ConfigManager::getBlockDurationSeconds() const {

    return blockDurationSeconds;
}


std::string ConfigManager::getDatabasePath() const {

    return databasePath;
}


std::string ConfigManager::getLogFile() const {

    return logFile;
}
