#include "packet_monitor.hpp"

#include <pcap/pcap.h>

#include <iostream>
#include <chrono>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

PacketMonitor::PacketMonitor(
    const std::string& interface,
    ConnectionTracker& tracker,
    Detector& detector
)
    : interfaceName(interface),
      connectionTracker(tracker),
      detector(detector) {
}

void PacketMonitor::processPacket(
    const unsigned char* packet,
    unsigned int length) {

    // Ethernet header = 14 bytes
    if (length < 14 + sizeof(struct ip))
        return;

    const struct ip* ipHeader =
        reinterpret_cast<const struct ip*>(
            packet + 14
        );

    // Only IPv4
    if (ipHeader->ip_v != 4)
        return;

    const unsigned int ipHeaderLength =
        ipHeader->ip_hl * 4;

    if (ipHeaderLength < 20)
        return;

    if (length < 14 + ipHeaderLength)
        return;

    char sourceIP[INET_ADDRSTRLEN];
    char destinationIP[INET_ADDRSTRLEN];

    if (!inet_ntop(
            AF_INET,
            &(ipHeader->ip_src),
            sourceIP,
            INET_ADDRSTRLEN)) {
        return;
    }

    if (!inet_ntop(
            AF_INET,
            &(ipHeader->ip_dst),
            destinationIP,
            INET_ADDRSTRLEN)) {
        return;
    }

    ConnectionEvent event;

    event.sourceIP = sourceIP;
    event.destinationIP = destinationIP;
    event.sourcePort = 0;
    event.destinationPort = 0;
    event.timestamp =
        std::chrono::system_clock::now();

    /*
     * TCP
     */
    if (ipHeader->ip_p == IPPROTO_TCP) {

        if (length <
            14 +
            ipHeaderLength +
            sizeof(struct tcphdr)) {
            return;
        }

        const struct tcphdr* tcpHeader =
            reinterpret_cast<const struct tcphdr*>(
                packet +
                14 +
                ipHeaderLength
            );

        event.sourcePort =
    ntohs(tcpHeader->source);

event.destinationPort =
    ntohs(tcpHeader->dest);

event.protocol = "TCP";

/*
 * Store whether this is an initial TCP SYN.
 *
 * SYN = connection attempt
 * ACK = response/established traffic
 */
bool initialSyn =
    (tcpHeader->syn != 0) &&
    (tcpHeader->ack == 0);

/*
 * Only send initial SYN packets to the
 * port-scan detector.
 */
if (!initialSyn) {

    connectionTracker.addConnection(event);

    return;
}
    }

    /*
     * UDP
     */
    else if (ipHeader->ip_p == IPPROTO_UDP) {

        if (length <
            14 +
            ipHeaderLength +
            sizeof(struct udphdr)) {
            return;
        }

        const struct udphdr* udpHeader =
            reinterpret_cast<const struct udphdr*>(
                packet +
                14 +
                ipHeaderLength
            );

        event.sourcePort =
            ntohs(udpHeader->source);

        event.destinationPort =
            ntohs(udpHeader->dest);

        event.protocol = "UDP";
    }

    /*
     * Ignore other protocols for connection tracking.
     */
    else {
        return;
    }

    std::cout
        << "[PACKET] "
        << event.sourceIP
        << " -> "
        << event.destinationIP
        << " "
        << event.protocol
        << " "
        << event.sourcePort
        << " -> "
        << event.destinationPort
        << std::endl;

    /*
     * Store connection.
     */
    connectionTracker.addConnection(event);

    /*
     * Send connection to detection engine.
     */
    detector.analyze(event);
}

void PacketMonitor::start() {

    char errorBuffer[PCAP_ERRBUF_SIZE];

    pcap_t* handle =
        pcap_open_live(
            interfaceName.c_str(),
            65535,
            1,
            1000,
            errorBuffer
        );

    if (!handle) {

        std::cerr
            << "Failed to open interface "
            << interfaceName
            << ": "
            << errorBuffer
            << std::endl;

        return;
    }

    std::cout
        << "========================================\n"
        << "       EMBEDDED LINUX NIDS\n"
        << "========================================\n"
        << "Interface : "
        << interfaceName
        << "\n"
        << "Packet capture started...\n"
        << "Press Ctrl+C to stop.\n"
        << "========================================\n";

    while (true) {

        struct pcap_pkthdr* header;
        const unsigned char* packet;

        int result =
            pcap_next_ex(
                handle,
                &header,
                &packet
            );

        if (result == 1) {

            processPacket(
                packet,
                header->caplen
            );
        }
        else if (result == 0) {

            continue;
        }
        else {

            std::cerr
                << "Packet capture stopped: "
                << pcap_geterr(handle)
                << std::endl;

            break;
        }
    }

    pcap_close(handle);
}
