#include "firewall_manager.hpp"

#include <cstdlib>
#include <iostream>


FirewallManager::FirewallManager() {

    // Create NIDS firewall table
    std::string createTable =
        "sudo nft add table inet " +
        tableName +
        " 2>/dev/null";

    std::system(
        createTable.c_str()
    );


    // Create blocked IP set with timeout support
    std::string createSet =
        "sudo nft add set inet " +
        tableName +
        " " +
        setName +
        " { type ipv4_addr\\; flags timeout\\; } "
        "2>/dev/null";

    std::system(
        createSet.c_str()
    );


    // Create input chain
    std::string createChain =
        "sudo nft add chain inet " +
        tableName +
        " input "
        "{ type filter hook input priority 0\\; policy accept\\; } "
        "2>/dev/null";

    std::system(
        createChain.c_str()
    );


    // Drop traffic from blocked IP addresses
    std::string addDropRule =
        "sudo nft add rule inet " +
        tableName +
        " input ip saddr @" +
        setName +
        " drop 2>/dev/null";

    std::system(
        addDropRule.c_str()
    );
}


bool FirewallManager::executeCommand(
    const std::string& command
) {

    int result =
        std::system(
            command.c_str()
        );

    return result == 0;
}


bool FirewallManager::blockIP(
    const std::string& ip,
    int durationSeconds
) {

    std::cout
        << "[FIREWALL] Blocking IP: "
        << ip
        << " for "
        << durationSeconds
        << " seconds."
        << std::endl;


    std::string command =
        "sudo nft add element inet " +
        tableName +
        " " +
        setName +
        " { " +
        ip +
        " timeout " +
        std::to_string(durationSeconds) +
        "s }";


    bool success =
        executeCommand(
            command
        );


    if (success) {

        std::cout
            << "[FIREWALL] IP blocked successfully."
            << std::endl;

    }
    else {

        std::cerr
            << "[FIREWALL] Failed to block IP."
            << std::endl;
    }


    return success;
}


bool FirewallManager::unblockIP(
    const std::string& ip
) {

    std::cout
        << "[FIREWALL] Unblocking IP: "
        << ip
        << std::endl;


    std::string command =
        "sudo nft delete element inet " +
        tableName +
        " " +
        setName +
        " { " +
        ip +
        " }";


    bool success =
        executeCommand(
            command
        );


    if (success) {

        std::cout
            << "[FIREWALL] IP unblocked successfully."
            << std::endl;

    }
    else {

        std::cerr
            << "[FIREWALL] Failed to unblock IP."
            << std::endl;
    }


    return success;
}


bool FirewallManager::isBlocked(
    const std::string& ip
) {

    std::string command =
        "sudo nft list set inet " +
        tableName +
        " " +
        setName +
        " | grep -q '" +
        ip +
        "'";


    return executeCommand(
        command
    );
}
