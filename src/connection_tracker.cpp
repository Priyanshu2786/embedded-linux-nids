#include "connection_tracker.hpp"

#include <algorithm>

void ConnectionTracker::addConnection(
    const ConnectionEvent& event) {

    connections.push_back(event);

    cleanup();
}


std::vector<ConnectionEvent>
ConnectionTracker::getRecentConnections(
    const std::string& sourceIP,
    int windowSeconds) {

    cleanup();

    const auto now =
        std::chrono::system_clock::now();

    std::vector<ConnectionEvent> result;

    for (const auto& connection : connections) {

        if (connection.sourceIP != sourceIP)
            continue;

        const auto age =
            std::chrono::duration_cast<
                std::chrono::seconds
            >(
                now -
                connection.timestamp
            ).count();

        if (age >= 0 &&
            age <= windowSeconds) {

            result.push_back(connection);
        }
    }

    return result;
}


size_t ConnectionTracker::totalConnections() const {

    return connections.size();
}


void ConnectionTracker::cleanup() {

    const auto now =
        std::chrono::system_clock::now();

    const auto expiration =
        now -
        std::chrono::seconds(60);

    connections.erase(
        std::remove_if(
            connections.begin(),
            connections.end(),
            [&](const ConnectionEvent& event) {

                return event.timestamp <
                       expiration;
            }
        ),
        connections.end()
    );
}
