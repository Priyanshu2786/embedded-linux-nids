#include "detector.hpp"

#include <algorithm>
#include <iostream>
#include <set>


Detector::Detector(
    int scanThreshold,
    int scanWindowSeconds,
    int connectionThreshold,
    int connectionWindowSeconds,
    Database& database,
    FirewallManager& firewallManager,
    bool autoBlock,
    int blockDurationSeconds,
    const std::vector<int>& suspiciousPorts
)
    : scanThreshold(scanThreshold),
      scanWindowSeconds(scanWindowSeconds),
      connectionThreshold(connectionThreshold),
      connectionWindowSeconds(connectionWindowSeconds),
      database(database),
      firewallManager(firewallManager),
      autoBlock(autoBlock),
      blockDurationSeconds(blockDurationSeconds),
      suspiciousPorts(suspiciousPorts) {
}


/* ============================================================
   MAIN ANALYSIS
   ============================================================ */

void Detector::analyze(
    const ConnectionEvent& event
) {

    detectSuspiciousPort(event);

    detectPortScan(event);

    detectConnectionRate(event);
}


/* ============================================================
   SUSPICIOUS PORT CHECK
   ============================================================ */

bool Detector::isSuspiciousPort(
    uint16_t port
) const {

    return std::find(
        suspiciousPorts.begin(),
        suspiciousPorts.end(),
        static_cast<int>(port)
    ) != suspiciousPorts.end();
}


/* ============================================================
   ALERT KEY
   ============================================================ */

std::string Detector::makeAlertKey(
    const std::string& sourceIP,
    const std::string& destinationIP
) const {

    return sourceIP + "->" + destinationIP;
}


/* ============================================================
   SUSPICIOUS PORT DETECTION
   ============================================================ */

void Detector::detectSuspiciousPort(
    const ConnectionEvent& event
) {

    if (!isSuspiciousPort(
            event.destinationPort)) {

        return;
    }


    const auto now =
        std::chrono::system_clock::now();


    const std::string key =
        makeAlertKey(
            event.sourceIP,
            event.destinationIP
        );


    auto lastAlert =
        lastSuspiciousPortAlertTime.find(key);


    /*
     * Avoid repeatedly logging the
     * same suspicious port.
     */

    if (lastAlert !=
        lastSuspiciousPortAlertTime.end()) {

        const auto elapsed =
            std::chrono::duration_cast<
                std::chrono::seconds
            >(
                now -
                lastAlert->second
            ).count();


        if (elapsed < 10) {

            return;
        }
    }


    lastSuspiciousPortAlertTime[key] =
        now;


    /*
     * Update cumulative risk.
     *
     * Suspicious Port = +20
     */

    const int riskScore =
        RiskEngine::updateRisk(
            event.sourceIP,
            false,
            true,
            false
        );


    const std::string riskLevel =
        RiskEngine::getRiskLevel(
            riskScore
        );


    std::cout
        << std::endl
        << "========================================"
        << std::endl
        << "       SUSPICIOUS PORT DETECTED"
        << std::endl
        << "========================================"
        << std::endl
        << "Event       : SUSPICIOUS_PORT"
        << std::endl
        << "Source IP   : "
        << event.sourceIP
        << std::endl
        << "Target IP   : "
        << event.destinationIP
        << std::endl
        << "Port        : "
        << event.destinationPort
        << std::endl
        << "Risk Score  : "
        << riskScore
        << "/100"
        << std::endl
        << "Risk Level  : "
        << riskLevel
        << std::endl
        << "Suspicious  : "
        << (
            RiskEngine::isSuspicious(
                riskScore
            )
            ? "YES"
            : "NO"
        )
        << std::endl
        << "Action      : ALERT"
        << std::endl
        << "========================================"
        << std::endl;


    database.logSecurityEvent(
        event.sourceIP,
        event.destinationIP,
        "SUSPICIOUS_PORT",
        riskScore,
        riskLevel,
        "ALERT"
    );
}


/* ============================================================
   PORT SCAN DETECTION
   ============================================================ */

void Detector::detectPortScan(
    const ConnectionEvent& event
) {

    const auto now =
        std::chrono::system_clock::now();


    auto& history =
        scanHistory[event.sourceIP];


    history.push_back({
        now,
        event.destinationIP,
        event.destinationPort
    });


    cleanup(event.sourceIP);


    std::set<uint16_t> uniquePorts;


    for (const auto& record : history) {

        if (record.destinationIP ==
            event.destinationIP) {

            uniquePorts.insert(
                record.destinationPort
            );
        }
    }


    std::cout
        << "[DETECTOR] "
        << event.sourceIP
        << " -> "
        << event.destinationIP
        << " | Unique ports: "
        << uniquePorts.size()
        << "/"
        << scanThreshold
        << " | Window: "
        << scanWindowSeconds
        << "s"
        << std::endl;


    if (static_cast<int>(
            uniquePorts.size()
        ) < scanThreshold) {

        return;
    }


    const std::string key =
        makeAlertKey(
            event.sourceIP,
            event.destinationIP
        );


    auto lastAlert =
        lastAlertTime.find(key);


    if (lastAlert !=
        lastAlertTime.end()) {

        const auto elapsed =
            std::chrono::duration_cast<
                std::chrono::seconds
            >(
                now -
                lastAlert->second
            ).count();


        if (elapsed < scanWindowSeconds) {

            return;
        }
    }


    lastAlertTime[key] =
        now;


    /*
     * Update cumulative risk.
     *
     * Port Scan = +40
     */

    const int riskScore =
        RiskEngine::updateRisk(
            event.sourceIP,
            true,
            false,
            false
        );


    const std::string riskLevel =
        RiskEngine::getRiskLevel(
            riskScore
        );


    std::cout
        << std::endl
        << "========================================"
        << std::endl
        << "       SECURITY ALERT"
        << std::endl
        << "========================================"
        << std::endl
        << "Event       : PORT_SCAN_DETECTED"
        << std::endl
        << "Source IP   : "
        << event.sourceIP
        << std::endl
        << "Target IP   : "
        << event.destinationIP
        << std::endl
        << "Unique Ports: "
        << uniquePorts.size()
        << std::endl
        << "Threshold   : "
        << scanThreshold
        << std::endl
        << "Window      : "
        << scanWindowSeconds
        << " seconds"
        << std::endl
        << "Risk Score  : "
        << riskScore
        << "/100"
        << std::endl
        << "Risk Level  : "
        << riskLevel
        << std::endl
        << "Suspicious  : "
        << (
            RiskEngine::isSuspicious(
                riskScore
            )
            ? "YES"
            : "NO"
        )
        << std::endl
        << "Auto Block  : "
        << (
            autoBlock
            ? "ENABLED"
            : "DISABLED"
        )
        << std::endl
        << "========================================"
        << std::endl;


    std::string action =
        "ALERT";


    /* ========================================================
       AUTOMATED FIREWALL RESPONSE
       ======================================================== */

    if (autoBlock) {

        std::cout
            << "       AUTOMATED RESPONSE"
            << std::endl
            << "========================================"
            << std::endl
            << "Blocking IP : "
            << event.sourceIP
            << std::endl
            << "Duration    : "
            << blockDurationSeconds
            << " seconds"
            << std::endl;


        if (firewallManager.blockIP(
                event.sourceIP,
                blockDurationSeconds)) {

            action =
                "BLOCKED";


            std::cout
                << "Action      : BLOCKED"
                << std::endl;

        }
        else {

            std::cout
                << "Action      : ALERT"
                << std::endl;
        }


        std::cout
            << "========================================"
            << std::endl;
    }


    database.logSecurityEvent(
        event.sourceIP,
        event.destinationIP,
        "PORT_SCAN_DETECTED",
        riskScore,
        riskLevel,
        action
    );
}


/* ============================================================
   CONNECTION RATE DETECTION
   ============================================================ */

void Detector::detectConnectionRate(
    const ConnectionEvent& event
) {

    const auto now =
        std::chrono::system_clock::now();


    auto& history =
        connectionHistory[event.sourceIP];


    history.push_back(now);


    cleanupConnectionHistory(
        event.sourceIP
    );


    const int connectionCount =
        static_cast<int>(
            history.size()
        );


    std::cout
        << "[CONNECTION RATE] "
        << event.sourceIP
        << " | Connections: "
        << connectionCount
        << "/"
        << connectionThreshold
        << " | Window: "
        << connectionWindowSeconds
        << "s"
        << std::endl;


    if (connectionCount <
        connectionThreshold) {

        return;
    }


    auto lastAlert =
        lastConnectionRateAlertTime.find(
            event.sourceIP
        );


    if (lastAlert !=
        lastConnectionRateAlertTime.end()) {

        const auto elapsed =
            std::chrono::duration_cast<
                std::chrono::seconds
            >(
                now -
                lastAlert->second
            ).count();


        if (elapsed <
            connectionWindowSeconds) {

            return;
        }
    }


    lastConnectionRateAlertTime[
        event.sourceIP
    ] = now;


    /*
     * Update cumulative risk.
     *
     * Connection Rate = +30
     */

    const int riskScore =
        RiskEngine::updateRisk(
            event.sourceIP,
            false,
            false,
            true
        );


    const std::string riskLevel =
        RiskEngine::getRiskLevel(
            riskScore
        );


    std::cout
        << std::endl
        << "========================================"
        << std::endl
        << "   CONNECTION RATE ANOMALY DETECTED"
        << std::endl
        << "========================================"
        << std::endl
        << "Event       : CONNECTION_RATE_ANOMALY"
        << std::endl
        << "Source IP   : "
        << event.sourceIP
        << std::endl
        << "Connections : "
        << connectionCount
        << std::endl
        << "Threshold   : "
        << connectionThreshold
        << std::endl
        << "Window      : "
        << connectionWindowSeconds
        << " seconds"
        << std::endl
        << "Risk Score  : "
        << riskScore
        << "/100"
        << std::endl
        << "Risk Level  : "
        << riskLevel
        << std::endl
        << "Suspicious  : "
        << (
            RiskEngine::isSuspicious(
                riskScore
            )
            ? "YES"
            : "NO"
        )
        << std::endl
        << "Action      : ALERT"
        << std::endl
        << "========================================"
        << std::endl;


    database.logSecurityEvent(
        event.sourceIP,
        event.destinationIP,
        "CONNECTION_RATE_ANOMALY",
        riskScore,
        riskLevel,
        "ALERT"
    );
}


/* ============================================================
   PORT SCAN HISTORY CLEANUP
   ============================================================ */

void Detector::cleanup(
    const std::string& sourceIP
) {

    const auto now =
        std::chrono::system_clock::now();


    auto& history =
        scanHistory[sourceIP];


    const auto expiration =
        now -
        std::chrono::seconds(
            scanWindowSeconds
        );


    history.erase(
        std::remove_if(
            history.begin(),
            history.end(),
            [&](const PortScanRecord& record) {

                return record.timestamp <
                       expiration;
            }
        ),
        history.end()
    );
}


/* ============================================================
   CONNECTION HISTORY CLEANUP
   ============================================================ */

void Detector::cleanupConnectionHistory(
    const std::string& sourceIP
) {

    const auto now =
        std::chrono::system_clock::now();


    auto& history =
        connectionHistory[sourceIP];


    const auto expiration =
        now -
        std::chrono::seconds(
            connectionWindowSeconds
        );


    history.erase(
        std::remove_if(
            history.begin(),
            history.end(),
            [&](const auto& timestamp) {

                return timestamp <
                       expiration;
            }
        ),
        history.end()
    );
}
