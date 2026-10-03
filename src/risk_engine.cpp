#include "risk_engine.hpp"

#include <algorithm>


std::unordered_map<
    std::string,
    RiskEngine::RiskState
> RiskEngine::riskStates;


/*
 * Calculate the risk score from individual indicators.
 *
 * Port Scan        = +40
 * Suspicious Port  = +20
 * Connection Rate  = +30
 *
 * Maximum score = 100
 */
int RiskEngine::calculateScore(
    bool portScan,
    bool suspiciousPort,
    bool connectionRate
) {

    int score = 0;

    if (portScan) {

        score += PORT_SCAN_SCORE;
    }

    if (suspiciousPort) {

        score += SUSPICIOUS_PORT_SCORE;
    }

    if (connectionRate) {

        score += CONNECTION_RATE_SCORE;
    }

    return std::min(score, 100);
}


/*
 * Convert score into a risk level.
 *
 * 0-19   = NORMAL
 * 20-59  = SUSPICIOUS
 * 60-100 = HIGH
 */
std::string RiskEngine::getRiskLevel(
    int score
) {

    if (score >= 60) {

        return "HIGH";
    }

    if (score >= 20) {

        return "SUSPICIOUS";
    }

    return "NORMAL";
}


/*
 * Determines whether the event should
 * be considered suspicious.
 */
bool RiskEngine::isSuspicious(
    int score
) {

    return score >= 20;
}


/*
 * Update the cumulative risk for a source IP.
 *
 * Each indicator is remembered for the risk window.
 *
 * Example:
 *
 * Suspicious Port
 *       +20
 *
 * Port Scan
 *       +40
 *
 * Total
 *       =60 HIGH
 */
int RiskEngine::updateRisk(
    const std::string& sourceIP,
    bool portScan,
    bool suspiciousPort,
    bool connectionRate
) {

    cleanupExpired(sourceIP);

    auto& state =
        riskStates[sourceIP];


    /*
     * Once an indicator is detected,
     * keep it active during the risk window.
     */

    state.portScan =
        state.portScan || portScan;


    state.suspiciousPort =
        state.suspiciousPort || suspiciousPort;


    state.connectionRate =
        state.connectionRate || connectionRate;


    state.lastUpdate =
        std::chrono::system_clock::now();


    /*
     * Calculate combined score.
     */

    return calculateScore(
        state.portScan,
        state.suspiciousPort,
        state.connectionRate
    );
}


/*
 * Remove expired risk information.
 *
 * Risk state is kept for 60 seconds.
 */
void RiskEngine::cleanupExpired(
    const std::string& sourceIP
) {

    auto iterator =
        riskStates.find(sourceIP);


    if (iterator ==
        riskStates.end()) {

        return;
    }


    const auto now =
        std::chrono::system_clock::now();


    const auto age =
        std::chrono::duration_cast<
            std::chrono::seconds
        >(
            now -
            iterator->second.lastUpdate
        ).count();


    if (age >= RISK_WINDOW_SECONDS) {

        riskStates.erase(iterator);
    }
}
