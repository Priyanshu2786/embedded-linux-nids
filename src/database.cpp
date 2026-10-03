#include "database.hpp"

#include <iostream>

Database::Database(
    const std::string& databasePath
)
    : databasePath(databasePath),
      db(nullptr) {
}

Database::~Database() {

    if (db != nullptr) {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool Database::initialize() {

    int result =
        sqlite3_open(
            databasePath.c_str(),
            &db
        );

    if (result != SQLITE_OK) {

        std::cerr
            << "[DATABASE] Failed to open database: "
            << sqlite3_errmsg(db)
            << std::endl;

        return false;
    }

    std::cout
        << "[DATABASE] SQLite database opened: "
        << databasePath
        << std::endl;

    return createTables();
}

bool Database::createTables() {

    const char* sql = R"SQL(

        CREATE TABLE IF NOT EXISTS security_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp DATETIME
                DEFAULT CURRENT_TIMESTAMP,

            source_ip TEXT NOT NULL,

            destination_ip TEXT NOT NULL,

            event_type TEXT NOT NULL,

            risk_score INTEGER NOT NULL,

            risk_level TEXT NOT NULL,

            action TEXT NOT NULL
        );

    )SQL";

    char* errorMessage = nullptr;

    int result =
        sqlite3_exec(
            db,
            sql,
            nullptr,
            nullptr,
            &errorMessage
        );

    if (result != SQLITE_OK) {

        std::cerr
            << "[DATABASE] Table creation failed: "
            << errorMessage
            << std::endl;

        sqlite3_free(errorMessage);

        return false;
    }

    std::cout
        << "[DATABASE] security_events table ready."
        << std::endl;

    return true;
}

bool Database::logSecurityEvent(
    const std::string& sourceIP,
    const std::string& destinationIP,
    const std::string& eventType,
    int riskScore,
    const std::string& riskLevel,
    const std::string& action
) {

    const char* sql = R"SQL(

        INSERT INTO security_events
        (
            source_ip,
            destination_ip,
            event_type,
            risk_score,
            risk_level,
            action
        )

        VALUES
        (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
        );

    )SQL";

    sqlite3_stmt* statement = nullptr;

    int result =
        sqlite3_prepare_v2(
            db,
            sql,
            -1,
            &statement,
            nullptr
        );

    if (result != SQLITE_OK) {

        std::cerr
            << "[DATABASE] Failed to prepare INSERT: "
            << sqlite3_errmsg(db)
            << std::endl;

        return false;
    }

    sqlite3_bind_text(
        statement,
        1,
        sourceIP.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text(
        statement,
        2,
        destinationIP.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text(
        statement,
        3,
        eventType.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_int(
        statement,
        4,
        riskScore
    );

    sqlite3_bind_text(
        statement,
        5,
        riskLevel.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text(
        statement,
        6,
        action.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    result =
        sqlite3_step(statement);

    sqlite3_finalize(statement);

    if (result != SQLITE_DONE) {

        std::cerr
            << "[DATABASE] Failed to insert security event."
            << std::endl;

        return false;
    }

    std::cout
        << "[DATABASE] Security event logged."
        << std::endl;

    return true;
}
