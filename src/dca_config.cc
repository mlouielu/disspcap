#include "dca_config.h"

namespace disspcap
{
DcaConfig::DcaConfig(uint8_t *data, const int data_length)
    : raw_header_{ reinterpret_cast<struct dca_config_ *>(data) },
      ptr_{ data },
      base_ptr_{ data },
      end_ptr_{ data + data_length }
{
    this->parse();
}

void DcaConfig::parse()
{
    this->header_ = this->raw_header_->header;
    this->cmd_ = this->raw_header_->cmd;
    this->status_ = (this->raw_header_->status & 0xFF) << 8 |
                    (this->raw_header_->status & 0xF00) >> 8;
    this->footer_ = this->raw_header_->footer;
}

}  // namespace disspcap
