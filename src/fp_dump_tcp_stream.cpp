//
// Created by lirui on 2018/8/11.
//

#include <functional>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <utility>

#include "pcap_loader.h"
#include "protocol_parser.h"
#include "tcp_protocol.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace fp = fast_pcap;

void filter_tcp_packet(const fp::pcap_file_ptr &pcap_file_ptr,
                       const std::function<void(const fp::protocol_header<fp::tcp_header_t> &)> &handler) {
    auto end = pcap_file_ptr->end();
    for (auto itr = pcap_file_ptr->begin(); itr != end; ++itr) {
        auto ethernet_header = fp::parse_protocol<fp::ethernet_header_t>(itr->content(), itr->length());
        if (ethernet_header->network_protocol_type == fp::ethernet_header_t::kProtocolIpv4) {
            auto ipv4_header = ethernet_header.unpack<fp::ipv4_header_t>();
            if (ipv4_header->protocol == fp::ipv4_header_t::kProtocolTcp) {
                auto tcp_header = ethernet_header.unpack<fp::tcp_header_t>();
                handler(tcp_header);
            }
        }
    }
}

class tcp_streamer {
public:
    explicit tcp_streamer(boost::filesystem::path output_dir) : output_dir(std::move(output_dir)) {
    }

public:
    void operator()(const fp::protocol_header<fp::tcp_header_t> &header) {

    }

private:
    const fs::path output_dir;
};

void dump_tcp_stream(const std::string &pcap_file_name, const std::string &dir_name) {
    auto dir = fs::path(dir_name);
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }

    auto pcap_file_ptr = fp::load_from_pcap_file(pcap_file_name);
    tcp_streamer streamer{dir_name};
    filter_tcp_packet(pcap_file_ptr, streamer);
}

int main(int argc, char *argv[]) {
    dump_tcp_stream("../data/traceroute.pcap", "../data/traceroute-pcap-output");
    return 0;
}
