#include <pybind11/pybind11.h>
#include <pybind11/numpy.h>
#include "dca_data.h"
#include "pcap.h"
#include <iostream>
#include "python_dca_user_lvds.h"

namespace py = pybind11;
using namespace disspcap;
py::array_t<int16_t> get_bytes_from_pcap_user_lvds(const std::string &filename)
{   
    disspcap::Pcap pcap(filename);
    std::vector<unsigned int> data_ports{4096,4098};
    pcap.dca_fetch_packets(data_ports);
    std::unique_ptr<DcaData> dd = pcap.get_dca_data(4098);
    dd->convert_int16();
    
    int16_t *ptr;
    ptr = dd->get_int16();

    py::array_t<int16_t> array(dd->received_rx_bytes()/2);
    auto r = array.mutable_unchecked<1>();

    // Populate the array with values
    for (ssize_t i = 0; i < dd->received_rx_bytes()/2; i++) {
        //r(i) = static_cast<int16_t>(*(ptr + i));

        ssize_t i_in_row = i%8;
        if (i_in_row==0 || i_in_row==3 || i_in_row==4 || i_in_row==7){
            r(i) = static_cast<int16_t>(*(ptr + i));
        }
        else{
            if (i_in_row==1 || i_in_row==5){
                r(i) = static_cast<int16_t>(*(ptr + i + 1));
            } else{
                r(i) = static_cast<int16_t>(*(ptr + i - 1));
            }
            
        }
    }
    
    return array;
}

