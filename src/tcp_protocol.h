//
// Created by lirui on 2018/8/10.
//

#ifndef FAST_PCAP_TCP_PROTOCOL_H
#define FAST_PCAP_TCP_PROTOCOL_H

#include "fpint.h"

#ifdef __unix__
#define PACKED __packed __aligned(1)
#else
#define PACKED
#endif

#ifdef _WIN32
#pragma pack(push, 1)
#endif

namespace fast_pcap {

struct ethernet_header_t {
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint16_t network_protocol_type;

    const static uint16_t kProtocolIpv4 = 0x0008;
    const static uint16_t kProtocolIpx = 0x3781;
    const static uint16_t kProtocolArp = 0x0608;
    const static uint16_t kProtocolPauseControl = 0x0888;
    const static uint16_t kProtocolIpv6 = 0xDD86;
} PACKED;

struct ipv4_header_t {
    uint8_t header_length:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flag_offset; // 3 bits flags and 13 bits fragment-offset
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;

    const static uint16_t kIpFlagReserved = 0x8000;
    const static uint16_t kIpFlagDoNotFragment = 0x4000;
    const static uint16_t kIpFlagMoreFragment = 0x2000;
    const static uint16_t kOffsetFragment = 0x1FFF;

    const static uint8_t kProtocolIcmp = 1;
    const static uint8_t kProtocolIgmp = 2;
    const static uint8_t kProtocolTcp = 6;
    const static uint8_t kProtocolUdp = 17;
    const static uint8_t kProtocolIgrp = 88;
    const static uint8_t kProtocolOspf = 89;
} PACKED;

struct tcp_header_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t syn_number;
    uint32_t ack_number;
    uint8_t reserved:4;
    uint8_t header_length:4;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;

    const static uint8_t kFlagsFin = 0x01;
    const static uint8_t kFlagsSyn = 0x02;
    const static uint8_t kFlagsRst = 0x04;
    const static uint8_t kFlagsPush = 0x08;
    const static uint8_t kFlagsAck = 0x10;
    const static uint8_t kFlagsUrg = 0x20;
    const static uint8_t kFlagsEce = 0x40;
    const static uint8_t kFlagsCwr = 0x80;

    inline bool flag_syn() const {
        return flags & kFlagsSyn;
    }

    inline bool flag_ack() const {
        return flags & kFlagsAck;
    }

    inline bool flag_rst() const {
        return flags & kFlagsRst;
    }

    inline bool flag_fin() const {
        return flags & kFlagsFin;
    }
} PACKED;

struct udp_header_t {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} PACKED;

struct icmp_header_t {
    uint8_t type;
    uint8_t code;
    uint16_t  checksum;
} PACKED;

}

#ifdef _WIN32
#pragma pack(pop)
#endif

#undef PACKED

#endif //FAST_PCAP_TCP_PROTOCOL_H
