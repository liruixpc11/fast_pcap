//
// Created by lirui on 2018/8/10.
//

#include "pcap_loader.h"
#include "protocol_parser.h"
#include "utils.h"
#include "tcp_protocol.h"

using namespace fast_pcap;

void demo() {
    pcap_file_ptr pcap_file = load_from_pcap_file("../data/traceroute.pcap");

    auto end = pcap_file->end();
    for (auto itr = pcap_file->begin(); itr != end; ++itr) {
        auto header = parse_protocol<ethernet_header_t>(itr->content(), itr->length());
        std::cout << header.header_size << std::endl;
        std::cout << header->network_protocol_type << std::endl;

        if (header->network_protocol_type == ethernet_header_t::kProtocolIpv4) {
            auto ip_header = header.unpack<ipv4_header_t>();
            std::cout << static_cast<uint32_t>(ip_header.header_size) << " "
                      << static_cast<uint32_t>(ip_header->version) << " "
                      << static_cast<uint32_t>(ip_header->header_length) << " "
                      << static_cast<uint32_t>(ip_header->protocol) << std::endl;

            if (ip_header->protocol == ipv4_header_t::kProtocolTcp) {
                auto tcp_header = header.unpack<tcp_header_t>();
                auto payload = tcp_header.payload();
            }
        }
    }
}

int main() {
    time_run(demo);
}