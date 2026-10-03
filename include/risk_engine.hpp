#ifndef RISK_ENGINE_HPP
#define RISK_ENGINE_HPP

#include <chrono>
#include <string>
#include <unordered_map>

class RiskEngine {

public:

    static constexpr int PORT_SCAN_SCORE = 40;
    static constexpr int SUSPICIOUS_PORT_SCORE = 20;
    static constexpr int CONNECTION_RATE_SCORE = 30;

    static constexpr int RISK_WINDOW_SECONDS = 60;

    static int calculateScore(
        bool portScan,
        bool suspiciousPort,
        bool connectionRate
    );

    static std::string getRiskLevel(
        int score
    );

    static bool isSuspicious(
        int score
    );

    static int updateRisk(
        const std::string& sourceIP,
        bool portScan,
        bool suspiciousPort,
        bool connectionRate
    );

private:

    struct RiskState {

        bool portScan = false;

        bool suspiciousPort = false;

        bool connectionRate = false;

        std::chrono::system_clock::time_point
            lastUpdate;
    };

    static std::unordered_map<
        std::string,
        RiskState
    > riskStates;

    static void cleanupExpired(
        const std::string& sourceIP
    );
};

#endif
