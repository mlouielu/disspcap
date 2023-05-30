#include "dca_data.h"
#include <iostream>

namespace disspcap
{

DcaData::DcaData() {}

void DcaData::add(const DcaRaw *raw)
{
    uint32_t seq_id = raw->seq_id();
    uint64_t byte_count = raw->byte_count();
    uint32_t payload_length = raw->payload_length();

    // Check if out-of-order
    if (seq_id != this->max_seq_id_ + 1) {
        out_of_order = true;
    }

    // Update maximum seq id and maximum tx bytes
    if (seq_id > this->max_seq_id_) {
        this->max_seq_id_ = seq_id;
        this->dca_report_tx_bytes_ = byte_count + payload_length;
    }

    this->raw_packets_.insert({ seq_id, raw });
    this->received_rx_bytes_ += payload_length;
}

int16_t *DcaData::convert_int16()
{
    if (!this->p_int16_) {
        this->p_int16_ =
            new int16_t[this->dca_report_tx_bytes_ /
                        DcaData::INT16_SIZE]();  // ISO C++03 5.3.4[expr.new]/15

        for (uint32_t i = 1; i <= this->max_seq_id_; ++i) {
            auto it = this->raw_packets_.find(i);
            if (it != this->raw_packets_.end()) {
                const DcaRaw *raw = it->second;
                uint32_t payload_length = raw->payload_length();
                uint32_t offset = raw->byte_count();
                memcpy(this->p_int16_ + offset / DcaData::INT16_SIZE,
                       raw->payload(), payload_length);
            }
        }
    }

    return this->p_int16_;
}

std::complex<float> *DcaData::convert_complex(const bool lsb_quadrature = true)
{
    if (!this->p_complex_) {
        auto iq_elems = this->dca_report_tx_bytes_ / DcaData::TI_COMPLEX_SIZE;
        this->p_complex_ = new std::complex<
            float>[iq_elems]();  // ISO C++03 5.3.4[expr.new]/15

        struct lvds_row *row;
        size_t index = 0;
        for (uint32_t i = 1; i <= this->max_seq_id_; ++i) {
            auto it = this->raw_packets_.find(i);
            if (it != this->raw_packets_.end()) {
                const DcaRaw *raw = it->second;
                uint32_t payload_length = raw->payload_length();
                uint32_t offset = raw->byte_count() / DcaData::TI_COMPLEX_SIZE;
                uint8_t *payload = raw->payload();
                for (uint32_t j = 0; j < payload_length;
                     j += DcaData::LVDS_ROW_SIZE) {
                    row = reinterpret_cast<struct lvds_row *>(payload + j);
                    index = offset + j / 4;


                    if (lsb_quadrature) {
                        /* LSB Q, MSB I */
                        this->p_complex_[index] = std::complex<float>(
                            row->lvds_l2_s1, row->lvds_l1_s1);
                        this->p_complex_[index + 1] = std::complex<float>(
                            row->lvds_l2_s2, row->lvds_l1_s2);
                    } else {
                        /* LSB I, MSB Q */
                        this->p_complex_[index] = std::complex<float>(
                            row->lvds_l1_s1, row->lvds_l2_s1);
                        this->p_complex_[index + 1] = std::complex<float>(
                            row->lvds_l1_s2, row->lvds_l2_s2);
                    }
                }
            }
        }
    }

    return this->p_complex_;
}

}  // namespace disspcap
