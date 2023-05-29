#ifndef DISSPCAP_DCA_RAW_H
#define DISSPCAP_DCA_RAW_H

#include <stdint.h>

namespace disspcap
{

struct dca_raw_ {
    uint32_t seq_id;
    uint64_t byte_count : 48;
} __attribute__((packed));

class DcaRaw
{
public:
    DcaRaw(uint8_t *data, int data_length);

    uint32_t seq_id() const { return seq_id_; }
    uint64_t byte_count() const { return byte_count_; }
    uint8_t *payload() const { return payload_; }
    uint32_t payload_length() const { return payload_length_; }

private:
    struct dca_raw_ *raw_header_;

    uint32_t seq_id_;
    uint64_t byte_count_;
    uint8_t *payload_;
    uint32_t payload_length_;

    const int HEADER_LENGTH = 10;
};

}  // namespace disspcap

#endif  // DISSPCAP_DCA_RAW_H
