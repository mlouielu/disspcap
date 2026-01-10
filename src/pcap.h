/**
 * @file pcap.h
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief Pcap handler.
 * @version 0.1
 * @date 2018-10-22
 *
 * @copyright Copyright (c) 2018
 *
 * Based on:
 * https://www.tcpdump.org/pcap.html
 */

#ifndef DISSPCAP_PCAP_H
#define DISSPCAP_PCAP_H

#include <pcap.h>
#include <stdint.h>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>

#include "dca_data.h"
#include "packet.h"

namespace disspcap
{

/**
 * @brief Pcap class for manipulating pcap files.
 */
class Pcap
{
public:
    Pcap();
    Pcap(const std::string &filename);
    ~Pcap();
    void open_pcap(const std::string &filename);
    std::unique_ptr<Packet> next_packet();

    /**
     * @brief Fetch all packets from pcap file.
     */
    void fetch_packets();

    /**
     * @brief Get raw bytes from given DCA1000EVM data port.
     *        Does not deal with out-of-order packets and missing packets.
     *        WARNING: Must call `fetch_packets()` first.
     *
     * @param port DCA1000EVM data port (UDP port number).
     */
    std::tuple<uint8_t *, uint64_t> get_raw_data(unsigned int port);

    /**
     * @brief Fetch all packets from DCA1000EVM data ports.
     *
     * @param data_ports DCA1000EVM data ports (UDP port numbers) to fetch.
     *                   WARNING: User will need to ensure there provide correct ports
     */
    void dca_fetch_packets(std::vector<unsigned int> data_ports);

    /**
     * @brief Get DcaData instance for given DCA1000EVM data port.
     *        WARNING: Must call `dca_fetch_packets()` first.
     *
     * @param port DCA1000EVM data port (UDP port number).
     */
    std::unique_ptr<DcaData> get_dca_data(unsigned int port);

    int last_packet_length() const;

private:
    pcap_t *pcap_;
    struct pcap_pkthdr *last_header_;
    char error_buffer_[PCAP_ERRBUF_SIZE];

    std::vector<std::unique_ptr<Packet>> packets_;
    std::unordered_map<int, std::unique_ptr<DcaData>> dca_dataset_;
};
}  // namespace disspcap

#endif
