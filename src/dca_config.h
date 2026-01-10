#ifndef DISSPCAP_DCA_CONFIG_H
#define DISSPCAP_DCA_CONFIG_H

#include <cstdint>

namespace disspcap
{

struct dca_config_ {
    uint16_t header;
    uint16_t cmd;
    uint16_t status;
    uint16_t footer;
};

class DcaConfig
{
public:
    DcaConfig(uint8_t *data, int data_length);
    void parse();

    uint16_t header() const { return header_; }
    uint16_t cmd() const { return cmd_; }
    uint16_t status() const { return status_; }
    uint16_t footer() const { return footer_; }

private:
    struct dca_config_ *raw_header_;
    uint8_t *ptr_;
    uint8_t *base_ptr_;
    uint8_t *end_ptr_;

    uint16_t header_;
    uint16_t cmd_;
    uint16_t status_;
    uint16_t footer_;
};

}  // namespace disspcap

#endif  // DISSPCAP_DCA_CONFIG_H
