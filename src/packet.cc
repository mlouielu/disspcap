/**
 * @file packet.c
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief Contains packet related representations.
 * @version 0.1
 * @date 2018-10-23
 *
 * @copyright Copyright (c) 2018
 */

#include "packet.h"

#include "ethernet.h"

namespace disspcap
{

/**
 * @brief Construct a new Packet:: Packet object and runs parser.
 *
 * @param length Packet length.
 */
Packet::Packet(uint8_t *data, unsigned int length)
    : length_{ length },
      payload_length_{ length },
      raw_data_{ data },
      ethernet_{ nullptr },
      ipv4_{ nullptr },
      ipv6_{ nullptr },
      udp_{ nullptr },
      tcp_{ nullptr },
      dns_{ nullptr },
      http_{ nullptr },
      irc_{ nullptr },
      telnet_{ nullptr },
      dca_config_{ nullptr },
      dca_raw_{ nullptr }
{
    if (!data) {
        return;
    }

    this->parse();
}

/**
 * @brief Construct a new Packet:: Packet object and runs parser.
 *
 * @param length Packet length.
 * @param ts Packet timestamp.
 */
Packet::Packet(uint8_t *data, unsigned int length, struct timeval ts)
    : length_{ length },
      payload_length_{ length },
      raw_data_{ data },
      ts_{ std::chrono::seconds{ ts.tv_sec } +
           std::chrono::microseconds{ ts.tv_usec } },
      ethernet_{ nullptr },
      ipv4_{ nullptr },
      ipv6_{ nullptr },
      udp_{ nullptr },
      tcp_{ nullptr },
      dns_{ nullptr },
      http_{ nullptr },
      irc_{ nullptr },
      telnet_{ nullptr },
      dca_config_{ nullptr },
      dca_raw_{ nullptr }
{
    if (!data) {
        return;
    }

    this->parse();
}

/**
 * @brief Destroy the Packet:: Packet object.
 *
 * Releases allocated memory for headers.
 */
Packet::~Packet()
{
    if (this->ethernet_)
        delete this->ethernet_;

    if (this->ipv4_)
        delete this->ipv4_;

    if (this->ipv6_)
        delete this->ipv6_;

    if (this->udp_)
        delete this->udp_;

    if (this->tcp_)
        delete this->tcp_;

    if (this->dns_)
        delete this->dns_;

    if (this->http_)
        delete this->http_;

    if (this->irc_)
        delete this->irc_;

    if (this->telnet_)
        delete this->telnet_;

    if (this->dca_config_)
        delete this->dca_config_;

    if (this->dca_raw_)
        delete this->dca_raw_;
}

/**
 * @brief Getter of packet length value.
 *
 * @return int Packet length.
 */
unsigned int Packet::length() const
{
    return this->length_;
}

/**
 * @brief Getter of payload length value.
 *
 * @return int Payload length (see Packet::payload()).
 */
unsigned int Packet::payload_length() const
{
    return this->payload_length_;
}

/**
 * @brief Getter of payload data (after last recognized header).
 *
 * @return uint8_t* Pointer to payload data.
 */
uint8_t *Packet::payload()
{
    return this->payload_;
}

/**
 * @brief Getter of raw data pointer.
 *
 * @return uint8_t* Pointer to raw data of packet.
 */
uint8_t *Packet::raw_data()
{
    return this->raw_data_;
}

/**
 * @brief Getter of ethernet header.
 *
 * @return const Ethernet* Ethernet header object.
 */
const Ethernet *Packet::ethernet() const
{
    return this->ethernet_;
}

/**
 * @brief Getter of IPv4 header.
 *
 * @return const IPv4* IPv4 header object.
 */
const IPv4 *Packet::ipv4() const
{
    return this->ipv4_;
}

/**
 * @brief Getter of IPv6 header.
 *
 * @return const IPv6* IPv6 header object.
 */
const IPv6 *Packet::ipv6() const
{
    return this->ipv6_;
}

/**
 * @brief Getter of UDP header.
 *
 * @return const UDP* UDP header object.
 */
const UDP *Packet::udp() const
{
    return this->udp_;
}

/**
 * @brief Getter of TCP header.
 *
 * @return const TCP* TCP header object.
 */
const TCP *Packet::tcp() const
{
    return this->tcp_;
}

/**
 * @brief Getter of DNS data.
 *
 * @return const DNS* DNS object.
 */
const DNS *Packet::dns() const
{
    return this->dns_;
}

/**
 * @brief Getter of HTTP data.
 *
 * @return const HTTP* HTTP object.
 */
const HTTP *Packet::http() const
{
    return this->http_;
}

/**
 * @brief Getter of IRC data.
 *
 * @return const IRC* IRC object.
 */
const IRC *Packet::irc() const
{
    return this->irc_;
}

/**
 * @brief Getter of Telnet data.
 *
 * @return const Telnet* Telnet object.
 */
const Telnet *Packet::telnet() const
{
    return this->telnet_;
}

const DcaConfig *Packet::dca_config() const
{
    return this->dca_config_;
}

const DcaRaw *Packet::dca_raw() const
{
    return this->dca_raw_;
}

const std::chrono::system_clock::time_point *Packet::ts() const
{
    return &this->ts_;
}

/**
 * @brief Parses raw data into protocol headers.
 */
void Packet::parse()
{
    this->payload_ = this->raw_data_;
    this->payload_length_ = this->length_;

    /* parse ethernet */
    this->ethernet_ = new Ethernet(this->raw_data_);

    if (!this->ethernet_) {
        return;
    }

    this->payload_ = this->ethernet_->payload();
    this->payload_length_ = this->length_ - ETH_LENGTH;

    std::string next_header;

    /* parse ip */
    if (this->ethernet_->type() == "IPv4") {
        this->ipv4_ = new IPv4(this->payload_);
        this->payload_ = this->ipv4_->payload();
        this->payload_length_ = this->ipv4_->payload_length();
        next_header = this->ipv4_->protocol();
    } else if (this->ethernet_->type() == "IPv6") {
        this->ipv6_ = new IPv6(this->payload_);
        this->payload_ = this->ipv6_->payload();
        this->payload_length_ = this->ipv6_->payload_length();
        next_header = this->ipv6_->next_header();
    }

    /* parse udp/tcp */
    if (next_header == "UDP") {
        this->udp_ = new UDP(this->payload_);
        this->payload_ = this->udp_->payload();
        this->payload_length_ = this->udp_->payload_length();

        /* Treat as DCA Config or DCA Raw */
        if (this->payload_length_ == 8) {
            this->dca_config_ =
                new DcaConfig(this->payload_, this->payload_length_);
        } else if (this->payload_length_ >= 10) {
            this->dca_raw_ = new DcaRaw(this->payload_, this->payload_length_);
            this->payload_ = this->dca_raw_->payload();
            this->payload_length_ = this->dca_raw_->payload_length();
        }
    }
}
}  // namespace disspcap
