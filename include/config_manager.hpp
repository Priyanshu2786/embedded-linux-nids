#ifndef CONFIG_MANAGER_HPP
#define CONFIG_MANAGER_HPP

#include <string>
#include <vector>

class ConfigManager {

public:

    explicit ConfigManager(
        const std::string& configPath
    );

    bool load();

    std::string getInterface() const;

    int getScanThreshold() const;

    int getScanWindowSeconds() const;

    int getConnectionThreshold() const;

    int getConnectionWindowSeconds() const;

    int getTrafficThresholdPPS() const;

    std::vector<int> getSuspiciousPorts() const;

    bool getAutoBlock() const;

    int getBlockDurationSeconds() const;

    std::string getDatabasePath() const;

    std::string getLogFile() const;

private:

    std::string configPath;

    std::string interfaceName;

    int scanThreshold;

    int scanWindowSeconds;

    int connectionThreshold;

    int connectionWindowSeconds;

    int trafficThresholdPPS;

    std::vector<int> suspiciousPorts;

    bool autoBlock;

    int blockDurationSeconds;

    std::string databasePath;

    std::string logFile;
};

#endif
