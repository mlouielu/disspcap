#ifndef DISSPCAP_DCA_DATA_H
#define DISSPCAP_DCA_DATA_H

#include "dca_raw.h"

#include <complex>
#include <cstdint>
#include <cstring>
#include <memory>
#include <unordered_map>

namespace disspcap
{

/// LVDS row, see p.10, SWRA581B, p.79, DCA1000EVM CLI Software Developer Guide
struct lvds_row {
    int16_t lvds_l1_s1;
    int16_t lvds_l1_s2;
    int16_t lvds_l2_s1;
    int16_t lvds_l2_s2;
};


/**
 * @brief DCA data, this ensure that the data is in order, add fill missing packets with zeros
 */
class DcaData
{
public:
    /* Const */
    static constexpr int INT16_SIZE = sizeof(int16_t); /* 2 bytes */
    static constexpr int TI_COMPLEX_SIZE = 4; /* 4 bytes, see p.4, SWRA581B */
    static constexpr int LVDS_ROW_SIZE = sizeof(struct lvds_row); /* 8 bytes */

    DcaData();
    ~DcaData()
    {
        if (p_int16_)
            delete[] p_int16_;
        if (p_complex_)
            delete[] p_complex_;
    }

    /// Add a raw packet to the data, and update the report
    /// Note: Assume that the raw packets are all from the same DCA1000EVM
    void add(const DcaRaw *raw);

    /// Convert raw packets to int16 array, if not allocated, allocate int16 array first
    int16_t *convert_int16();

    /// Convert raw packets to complex array, if not allocated, allocate complex array first
    /// @param lsb_quadrature:
    ///     true if Q in LSB, I in MSB (mmwave SDK default),
    ///     false if I in LSB, Q in MSB (mmwave studio default)
    std::complex<float> *convert_complex(const bool lsb_quadrature);

    /// Get the int16 array
    int16_t *get_int16() { return this->p_int16_; }

    /// Get the complex array
    std::complex<float> *get_complex() { return this->p_complex_; }

    const uint64_t dca_report_tx_bytes() const
    {
        return this->dca_report_tx_bytes_;
    }
    const uint64_t received_rx_bytes() const
    {
        return this->received_rx_bytes_;
    }
    const uint32_t max_seq_id() const { return this->max_seq_id_; }
    const bool is_out_of_order() const { return this->out_of_order; }

private:
    std::unordered_map<uint32_t, const DcaRaw *> raw_packets_;

    /// Total received bytes from packets (+ payload length)
    uint64_t received_rx_bytes_ = 0;

    /// Observed largest sequence id packet: DCA report tx bytes + it's payload length
    /// Use this to allocate memory for complex numbers
    uint64_t dca_report_tx_bytes_ = 0;

    /// Observed largest sequence id
    uint32_t max_seq_id_ = 0;

    /* Report */
    /// True if packets are out of order
    bool out_of_order = false;

    /* Data */
    /// Raw data without complex conversion
    /// The layout of is: [LVDS L1 Sample 1, LVDS L1 Sample 2, LVDS L2 Sample 1, LVDS L2 Sample 2, ...]
    int16_t *p_int16_ = nullptr;

    /// Complex numbers, with non-interleaved to interleaved conversion
    /// The layout is: [IQ (sample 1), IQ (sample 2), ...]
    std::complex<float> *p_complex_ = nullptr;
};

}  // namespace disspcap

#endif  //DISSPCAP_DCA_DATA_H
