#include <pybind11/pybind11.h>
#include <pybind11/numpy.h>

namespace py = pybind11;

py::array_t<int16_t> get_bytes_from_pcap_user_lvds(const std::string &filename);
