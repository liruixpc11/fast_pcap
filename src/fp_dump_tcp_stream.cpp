//
// Created by lirui on 2018/8/11.
//

#include <functional>
#include <unordered_map>

#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/functional.hpp>
#include <boost/functional/hash.hpp>
#include <utility>

#include "pcap_loader.h"
#include "protocol_parser.h"
#include "tcp_protocol.h"
#include "utils.h"

namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace fp = fast_pcap;

using boost::format;
using boost::lexical_cast;

using namespace std::placeholders;

void filter_tcp_packet(const fp::pcap_file_ptr &pcap_file_ptr,
                       const std::function<void(const fp::protocol_header<fp::ipv4_header_t> &,
                                                const fp::protocol_header<fp::tcp_header_t> &)> &handler) {
    auto end = pcap_file_ptr->end();
    for (auto itr = pcap_file_ptr->begin(); itr != end; ++itr) {
        auto ethernet_header = fp::parse_protocol<fp::ethernet_header_t>(itr->content(), itr->length());
        if (ethernet_header->network_protocol_type == fp::ethernet_header_t::kProtocolIpv4) {
            auto ipv4_header = ethernet_header.unpack<fp::ipv4_header_t>();
            if (ipv4_header->protocol == fp::ipv4_header_t::kProtocolTcp) {
                auto tcp_header = ipv4_header.unpack<fp::tcp_header_t>();
                handler(ipv4_header, tcp_header);
            }
        }
    }
}

struct tcp_connection_tuple_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    tcp_connection_tuple_t() {}

    tcp_connection_tuple_t(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
        if (src_ip <= dst_ip) {
            this->src_ip = src_ip;
            this->dst_ip = dst_ip;
            this->src_port = src_port;
            this->dst_port = dst_port;
        } else {
            this->src_ip = dst_ip;
            this->dst_ip = src_ip;
            this->src_port = dst_port;
            this->dst_port = src_port;
        }
    }

    bool operator==(const tcp_connection_tuple_t &rhs) const {
        return src_ip == rhs.src_ip &&
               dst_ip == rhs.dst_ip &&
               src_port == rhs.src_port &&
               dst_port == rhs.dst_port;
    }

    bool operator!=(const tcp_connection_tuple_t &rhs) const {
        return !(rhs == *this);
    }
};

struct tcp_connection_tuple_hash {
    std::size_t operator()(const tcp_connection_tuple_t &t) const {
        using boost::hash_value;
        using boost::hash_combine;

        std::size_t seed = 0;
        hash_combine(seed, hash_value(t.src_ip));
        hash_combine(seed, hash_value(t.dst_ip));
        hash_combine(seed, hash_value(t.src_port));
        hash_combine(seed, hash_value(t.dst_port));

        return seed;
    }
};

struct tcp_connection_state_t {
    tcp_connection_tuple_t tuple;

    uint32_t index;

    uint32_t init_syn_number;
    uint32_t syn_number;

    uint32_t init_ack_number;
    uint32_t ack_number;

    FILE *send_file;
    FILE *recv_file;

    tcp_connection_state_t() {}

    tcp_connection_state_t(const tcp_connection_tuple_t &tuple,
                           uint32_t index,
                           uint32_t init_syn_number,
                           uint32_t init_ack_number)
            : tuple(tuple),
              index(index),
              init_syn_number(init_syn_number),
              syn_number(init_syn_number),
              init_ack_number(init_ack_number),
              ack_number(init_ack_number),
              send_file(nullptr),
              recv_file(nullptr) {
    };
};

class tcp_streamer {
public:
    explicit tcp_streamer(boost::filesystem::path output_dir)
            : output_dir_(std::move(output_dir)),
              state_map_(),
              next_index_(1) {
    }

public:
    void operator()(const fp::protocol_header<fp::ipv4_header_t> &ipv4_header,
                    const fp::protocol_header<fp::tcp_header_t> &tcp_header) {
        tcp_connection_tuple_t conn_tuple(ipv4_header->src_addr,
                                          ipv4_header->dst_addr,
                                          tcp_header->src_port,
                                          tcp_header->dst_port);
        auto itr = state_map_.find(conn_tuple);
        if (itr == state_map_.end()) {
            new_state(conn_tuple, ipv4_header, tcp_header);
        } else {
            tcp_connection_state_t &state = itr->second;

            auto payload = tcp_header.payload();
            uint32_t syn_number = fp::adjust_endian(tcp_header->syn_number);
            if (ipv4_header->src_addr == conn_tuple.src_ip) {
                if (syn_number <= state.syn_number) {
                    uint32_t overlap = state.syn_number - syn_number;
                    if (overlap < static_cast<uint32_t >(payload.size())) {
                        std::size_t bytes = ::fwrite(payload.data() + overlap, 1, payload.size() - overlap,
                                                     state.send_file);
                        state.syn_number += bytes;
                    }
                } else if (state.syn_number == 0 && ::ftell(state.send_file) == 0) {
                    ::fwrite(payload.data(), 1, payload.size(), state.send_file);
                    state.syn_number = syn_number + static_cast<uint32_t>(payload.size());
                } else {
                    std::cout << std::hex << state.syn_number << " "
                              << std::hex << syn_number << " "
                              << std::dec << syn_number - state.syn_number << " | "
                              << payload.size() << std::endl;
                    new_state(conn_tuple, ipv4_header, tcp_header);
                }
            } else {
                if (syn_number <= state.ack_number) {
                    uint32_t overlap = state.ack_number - syn_number;
                    if (overlap < static_cast<uint32_t >(payload.size())) {
                        std::size_t bytes = ::fwrite(payload.data() + overlap, 1, payload.size() - overlap,
                                                     state.recv_file);
                        state.ack_number += bytes;
                    }
                } else if (state.ack_number == 0 && ::ftell(state.recv_file) == 0) {
                    ::fwrite(payload.data(), 1, payload.size(), state.recv_file);
                    state.ack_number = syn_number + static_cast<uint32_t>(payload.size());
                } else {
                    std::cout << std::hex << state.syn_number << " "
                              << std::hex << syn_number << " "
                              << std::dec << syn_number - state.syn_number << " | "
                              << payload.size() << std::endl;
                    new_state(conn_tuple, ipv4_header, tcp_header);
                }
            }
        }
    }

    void finish() {
        std::for_each(state_map_.begin(), state_map_.end(), [this](auto pair) {
            close_files(pair.second);
        });
    }

private:
    void new_state(const tcp_connection_tuple_t &conn_tuple,
                   const fp::protocol_header<fp::ipv4_header_t> &ipv4_header,
                   const fp::protocol_header<fp::tcp_header_t> &tcp_header) {
        uint32_t syn_number, ack_number;
        if (ipv4_header->src_addr == conn_tuple.src_ip) {
            syn_number = fp::adjust_endian(tcp_header->syn_number);
            ack_number = fp::adjust_endian(tcp_header->ack_number);
        } else {
            syn_number = fp::adjust_endian(tcp_header->ack_number);
            ack_number = fp::adjust_endian(tcp_header->syn_number);
        }

        tcp_connection_state_t state(conn_tuple, next_index_++, syn_number, ack_number);

        auto send_file_path = output_dir_;
        send_file_path /= (format("%1%-%2%.%3%-%4%.%5%.bin")
                           % state.index
                           % fp::ipv4_str(conn_tuple.src_ip)
                           % conn_tuple.src_port
                           % fp::ipv4_str(conn_tuple.dst_ip)
                           % conn_tuple.dst_port).str();

        auto recv_file_path = output_dir_;
        recv_file_path /= (format("%1%-%2%.%3%-%3%.%5%.bin")
                           % state.index
                           % fp::ipv4_str(conn_tuple.dst_ip)
                           % conn_tuple.dst_port
                           % fp::ipv4_str(conn_tuple.src_ip)
                           % conn_tuple.src_port).str();

        state.send_file = ::fopen(send_file_path.c_str(), "wb");
        state.recv_file = ::fopen(recv_file_path.c_str(), "wb");

        auto payload = tcp_header.payload();
        if (payload.size() > 0) {
            if (ipv4_header->src_addr == conn_tuple.src_ip) {
                ::fwrite(payload.data(), 1, payload.size(), state.send_file);
            } else {
                ::fwrite(payload.data(), 1, payload.size(), state.recv_file);
            }
        } else if (tcp_header->flag_syn()) {
            // 跳过三次握手
            if (ipv4_header->src_addr == conn_tuple.src_ip) {
                state.syn_number += 1;
            } else {
                state.ack_number += 1;
            }
        }

        auto itr = state_map_.find(conn_tuple);
        if (itr != state_map_.end()) {
            close_files(itr->second);
        }

        state_map_[conn_tuple] = state;
    }

    void close_files(tcp_connection_state_t &state) {
        if (state.send_file) {
            ::fclose(state.send_file);
        }

        if (state.recv_file) {
            ::fclose(state.recv_file);
        }
    }

private:
    typedef std::unordered_map<tcp_connection_tuple_t, tcp_connection_state_t, tcp_connection_tuple_hash> tcp_state_map_t;
    const fs::path output_dir_;
    tcp_state_map_t state_map_;
    uint32_t next_index_;
};

void dump_tcp_stream(const std::string &pcap_file_name, const std::string &dir_name) {
    auto dir = fs::path(dir_name);
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }

    auto pcap_file_ptr = fp::load_from_pcap_file(pcap_file_name);
    tcp_streamer streamer{dir_name};
    filter_tcp_packet(pcap_file_ptr, streamer);
    streamer.finish();
}

int main(int argc, char *argv[]) {
    std::cout << sizeof(fp::ethernet_header_t) << " "
              << sizeof(fp::ipv4_header_t) << " "
              << sizeof(fp::tcp_header_t) << std::endl;
    try {
        fp::time_run([]() {
            dump_tcp_stream("../data/traceroute.pcap", "../data/traceroute-pcap-output");
        });
        fp::time_run([]() {
            dump_tcp_stream("../data/LLS_DDOS_1.0-dmz.dump", "../data/LLS_DDOS_1.0-dmz-dump-output");
        });
    } catch (std::exception &ex) {
        std::cout << ex.what() << std::endl;
    }
    return 0;
}
