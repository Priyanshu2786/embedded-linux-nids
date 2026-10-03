#ifndef DATABASE_HPP
#define DATABASE_HPP

#include <string>
#include <sqlite3.h>

class Database {

public:

    explicit Database(
        const std::string& databasePath
    );

    ~Database();

    bool initialize();

    bool logSecurityEvent(
        const std::string& sourceIP,
        const std::string& destinationIP,
        const std::string& eventType,
        int riskScore,
        const std::string& riskLevel,
        const std::string& action
    );

private:

    std::string databasePath;

    sqlite3* db;

    bool createTables();
};

#endif
