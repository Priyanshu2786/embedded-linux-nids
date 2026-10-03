#include <sqlite3.h>

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>


const std::string DATABASE =
    "data/nids.db";


/* ============================================================
   PRINT HEADER
   ============================================================ */

void printHeader(
    const std::string& title
) {

    std::cout
        << std::endl
        << "========================================"
        << std::endl
        << "       EMBEDDED LINUX NIDS CLI"
        << std::endl
        << "========================================"
        << std::endl
        << title
        << std::endl
        << "========================================"
        << std::endl;
}


/* ============================================================
   DATABASE OPEN
   ============================================================ */

sqlite3* openDatabase()
{
    sqlite3* database = nullptr;

    if (sqlite3_open(
            DATABASE.c_str(),
            &database) != SQLITE_OK) {

        std::cerr
            << "[ERROR] Cannot open database: "
            << sqlite3_errmsg(database)
            << std::endl;

        if (database) {
            sqlite3_close(database);
        }

        return nullptr;
    }

    return database;
}


/* ============================================================
   STATUS
   ============================================================ */

void showStatus()
{
    printHeader(
        "SYSTEM STATUS"
    );

    std::cout
        << "NIDS Engine       : Available"
        << std::endl
        << "Database          : "
        << DATABASE
        << std::endl
        << "Detection Modules :"
        << std::endl
        << "  - Suspicious Port"
        << std::endl
        << "  - Port Scan"
        << std::endl
        << "  - Connection Rate"
        << std::endl
        << "Risk Engine       : Active"
        << std::endl
        << "Firewall Response : nftables"
        << std::endl
        << "========================================"
        << std::endl;
}


/* ============================================================
   ALERTS
   ============================================================ */

void showAlerts()
{
    printHeader(
        "RECENT SECURITY ALERTS"
    );

    sqlite3* database =
        openDatabase();

    if (!database) {
        return;
    }


    const char* sql =
        "SELECT "
        "timestamp, "
        "source_ip, "
        "destination_ip, "
        "event_type, "
        "risk_score, "
        "risk_level, "
        "action "
        "FROM security_events "
        "ORDER BY id DESC "
        "LIMIT 20;";


    sqlite3_stmt* statement =
        nullptr;


    if (sqlite3_prepare_v2(
            database,
            sql,
            -1,
            &statement,
            nullptr) != SQLITE_OK) {

        std::cerr
            << "[ERROR] Failed to query alerts."
            << std::endl;

        sqlite3_close(database);

        return;
    }


    std::cout
        << std::left
        << std::setw(20)
        << "TIME"
        << std::setw(18)
        << "SOURCE"
        << std::setw(18)
        << "DESTINATION"
        << std::setw(26)
        << "EVENT"
        << std::setw(8)
        << "SCORE"
        << std::setw(12)
        << "LEVEL"
        << "ACTION"
        << std::endl;


    std::cout
        << "--------------------------------------------------------------------------------"
        << std::endl;


    bool found = false;


    while (
        sqlite3_step(statement)
        == SQLITE_ROW) {

        found = true;


        const char* timestamp =
            reinterpret_cast<const char*>(
                sqlite3_column_text(
                    statement,
                    0
                )
            );


        const char* source =
            reinterpret_cast<const char*>(
                sqlite3_column_text(
                    statement,
                    1
                )
            );


        const char* destination =
            reinterpret_cast<const char*>(
                sqlite3_column_text(
                    statement,
                    2
                )
            );


        const char* event =
            reinterpret_cast<const char*>(
                sqlite3_column_text(
                    statement,
                    3
                )
            );


        int score =
            sqlite3_column_int(
                statement,
                4
            );


        const char* level =
            reinterpret_cast<const char*>(
                sqlite3_column_text(
                    statement,
                    5
                )
            );


        const char* action =
            reinterpret_cast<const char*>(
                sqlite3_column_text(
                    statement,
                    6
                )
            );


        std::cout
            << std::left
            << std::setw(20)
            << (timestamp ? timestamp : "")
            << std::setw(18)
            << (source ? source : "")
            << std::setw(18)
            << (destination ? destination : "")
            << std::setw(26)
            << (event ? event : "")
            << std::setw(8)
            << score
            << std::setw(12)
            << (level ? level : "")
            << (action ? action : "")
            << std::endl;
    }


    if (!found) {

        std::cout
            << "No security alerts found."
            << std::endl;
    }


    sqlite3_finalize(statement);

    sqlite3_close(database);
}


/* ============================================================
   STATISTICS
   ============================================================ */

void showStats()
{
    printHeader(
        "SECURITY STATISTICS"
    );


    sqlite3* database =
        openDatabase();


    if (!database) {
        return;
    }


    const char* sql =
        "SELECT "
        "COUNT(*), "
        "SUM(CASE WHEN event_type = "
        "'PORT_SCAN_DETECTED' "
        "THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN event_type = "
        "'SUSPICIOUS_PORT' "
        "THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN event_type = "
        "'CONNECTION_RATE_ANOMALY' "
        "THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN action = "
        "'BLOCKED' "
        "THEN 1 ELSE 0 END) "
        "FROM security_events;";


    sqlite3_stmt* statement =
        nullptr;


    if (sqlite3_prepare_v2(
            database,
            sql,
            -1,
            &statement,
            nullptr) != SQLITE_OK) {

        std::cerr
            << "[ERROR] Failed to calculate statistics."
            << std::endl;

        sqlite3_close(database);

        return;
    }


    if (sqlite3_step(statement)
        == SQLITE_ROW) {

        int total =
            sqlite3_column_int(
                statement,
                0
            );

        int portScans =
            sqlite3_column_int(
                statement,
                1
            );

        int suspiciousPorts =
            sqlite3_column_int(
                statement,
                2
            );

        int connectionAnomalies =
            sqlite3_column_int(
                statement,
                3
            );

        int blocked =
            sqlite3_column_int(
                statement,
                4
            );


        std::cout
            << "Total Security Events : "
            << total
            << std::endl
            << "Port Scan Events      : "
            << portScans
            << std::endl
            << "Suspicious Port Events: "
            << suspiciousPorts
            << std::endl
            << "Connection Anomalies  : "
            << connectionAnomalies
            << std::endl
            << "Blocked IP Events     : "
            << blocked
            << std::endl;
    }


    sqlite3_finalize(statement);

    sqlite3_close(database);


    std::cout
        << "========================================"
        << std::endl;
}


/* ============================================================
   BLOCKED IPs
   ============================================================ */

void showBlocked()
{
    printHeader(
        "BLOCKED IP ADDRESSES"
    );


    std::cout
        << "Reading nftables..."
        << std::endl
        << std::endl;


    int result =
        std::system(
            "sudo nft list set inet nids blocked_ips"
        );


    if (result != 0) {

        std::cerr
            << "[ERROR] Unable to read nftables blocked IP set."
            << std::endl;
    }


    std::cout
        << "========================================"
        << std::endl;
}


/* ============================================================
   HELP
   ============================================================ */

void showHelp(
    const char* program
)
{
    std::cout
        << std::endl
        << "Embedded Linux NIDS CLI"
        << std::endl
        << std::endl
        << "Usage:"
        << std::endl
        << "  "
        << program
        << " status"
        << std::endl
        << "  "
        << program
        << " alerts"
        << std::endl
        << "  "
        << program
        << " stats"
        << std::endl
        << "  "
        << program
        << " blocked"
        << std::endl
        << std::endl
        << "Commands:"
        << std::endl
        << "  status   Show NIDS system status"
        << std::endl
        << "  alerts   Show recent security alerts"
        << std::endl
        << "  stats    Show security statistics"
        << std::endl
        << "  blocked  Show nftables blocked IPs"
        << std::endl;
}


/* ============================================================
   MAIN
   ============================================================ */

int main(
    int argc,
    char* argv[]
)
{
    if (argc < 2) {

        showHelp(argv[0]);

        return 0;
    }


    std::string command =
        argv[1];


    if (command == "status") {

        showStatus();
    }

    else if (command == "alerts") {

        showAlerts();
    }

    else if (command == "stats") {

        showStats();
    }

    else if (command == "blocked") {

        showBlocked();
    }

    else if (
        command == "help" ||
        command == "--help" ||
        command == "-h") {

        showHelp(argv[0]);
    }

    else {

        std::cerr
            << "[ERROR] Unknown command: "
            << command
            << std::endl;

        showHelp(argv[0]);

        return 1;
    }


    return 0;
}
