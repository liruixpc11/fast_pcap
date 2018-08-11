//
// Created by lirui on 2018/8/10.
//

#include <cstdio>
#include <boost/format.hpp>
#include <iostream>
#include "pcap_loader.h"
#include "utils.h"

using boost::uint8_t;
using boost::uint16_t;
using boost::uint32_t;

using std::fopen;
using std::fread;
using std::fclose;

namespace fast_pcap {

struct pcap_file_impl {
    ::FILE *file;
};

}

namespace {

#ifdef __unix__
#define FP_PACKED __packed __aligned(4)
#else
#define FP_PACKED
#endif

#ifdef _WIN32
#pragma pack(push, 1)
#endif

struct pcap_header_t {
    const static uint32_t kMagicNumberLittle = 0xa1b2c3d4;
    const static uint32_t kMagicNumberBig = 0xd4c3b2a1;

    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t zone;
    uint32_t reserved;
    uint32_t snap_length;
    uint32_t network;
} FP_PACKED;

const std::size_t pcap_header_size = sizeof(pcap_header_t);

struct packet_header_t {
    uint32_t seconds;
    uint32_t micro_seconds;
    uint32_t include_length;
    uint32_t actual_length;
};

const std::size_t packet_header_size = sizeof(packet_header_t);

#ifdef _WIN32
#pragma pack(pop)
#endif

#undef FP_PACKED

fast_pcap::pcap_frame_ptr read_frame(const fast_pcap::pcap_file *pcap_f) {
    packet_header_t packet_header;
    auto bytes = ::fread(&packet_header, 1, packet_header_size, pcap_f->impl()->file);
    if (bytes == 0) {
        return fast_pcap::pcap_frame_ptr();
    }

    if (bytes != packet_header_size) {
        throw fast_pcap::pcap_load_error((boost::format("read packet header, expected %1 bytes, got %2 bytes")
                               % packet_header_size
                               % bytes).str()
        );
    }

    bool little_endian = pcap_f->little_endian();
    std::size_t include_length = fast_pcap::adjust_endian(packet_header.include_length, little_endian);
    std::size_t actual_length = fast_pcap::adjust_endian(packet_header.actual_length, little_endian);
    uint32_t seconds = fast_pcap::adjust_endian(packet_header.seconds, little_endian);
    uint32_t micro_seconds = fast_pcap::adjust_endian(packet_header.micro_seconds, little_endian);

    fast_pcap::pcap_frame_ptr ptr(new fast_pcap::pcap_frame(actual_length, seconds, micro_seconds));
    bytes = ::fread(ptr->buffer(), 1, include_length, pcap_f->impl()->file);
    if (bytes != include_length) {
        throw fast_pcap::pcap_load_error(
                (boost::format("read packet content failed, expected %1 bytes, got %2 bytes")
                        % include_length
                        % bytes
                ).str()
        );
    }

    return ptr;
}

}

namespace fast_pcap {

pcap_file_ptr load_from_pcap_file(const std::string &file_name) {
    pcap_header_t pcap_header;

    auto f = fopen(file_name.c_str(), "rb");
    if (f == nullptr) {
        throw pcap_load_error((boost::format("open file %1 failed")
                               % file_name).str()
        );
    }

    auto bytes = fread(&pcap_header, 1, pcap_header_size, f);
    if (bytes != pcap_header_size) {
        throw pcap_load_error((boost::format("read pcap header, expected %1 bytes, got %2 bytes")
                               % pcap_header_size
                               % bytes).str()
        );
    }

    bool little_endian = pcap_header_t::kMagicNumberLittle == pcap_header.magic_number;
    int version_major = adjust_endian(pcap_header.version_major, little_endian);
    int version_minor = adjust_endian(pcap_header.version_minor, little_endian);

    auto *impl = new pcap_file_impl{f};
    return std::make_shared<fast_pcap::pcap_file>(little_endian, version_major, version_minor, impl);

}

pcap_file::~pcap_file() {
    ::fclose(impl_->file);
    delete impl_;
}

pcap_file::const_iterator pcap_file::begin() const {
    return pcap_iterator(this);
}

pcap_file::const_iterator pcap_file::end() const {
    return fast_pcap::pcap_file::const_iterator();
}

pcap_iterator::pcap_iterator(const pcap_file *file)
        : file_(file) {
    frame_ = read_frame(file);
}

pcap_iterator::self_type pcap_iterator::operator++() {
    frame_ = read_frame(file_);
    return *this;
}

bool pcap_iterator::operator==(const pcap_iterator::self_type &other) {
    return frame_ == other.frame_;
}

bool pcap_iterator::operator!=(const pcap_iterator::self_type &other) {
    return frame_ != other.frame_;
}

}

