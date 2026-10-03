#ifndef FIREWALL_MANAGER_HPP
#define FIREWALL_MANAGER_HPP

#include <string>

class FirewallManager {

public:

    FirewallManager();

    bool blockIP(
        const std::string& ip,
        int durationSeconds
    );

    bool unblockIP(
        const std::string& ip
    );

    bool isBlocked(
        const std::string& ip
    );

private:

    const std::string tableName =
        "nids";

    const std::string setName =
        "blocked_ips";

    bool executeCommand(
        const std::string& command
    );
};

#endif
