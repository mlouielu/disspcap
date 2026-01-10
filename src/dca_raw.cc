#include "dca_raw.h"

namespace disspcap
{
DcaRaw::DcaRaw(uint8_t *data, int data_length)
    : raw_header_{ reinterpret_cast<struct dca_raw_ *>(data) }
{
    this->seq_id_ = this->raw_header_->seq_id;
    this->byte_count_ = this->raw_header_->byte_count;
    this->payload_ = data + DcaRaw::HEADER_LENGTH;
    this->payload_length_ = data_length - DcaRaw::HEADER_LENGTH;
}

}  // namespace disspcap
