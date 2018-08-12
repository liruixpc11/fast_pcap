//
// Created by lirui on 2018/8/10.
//

#ifndef FAST_PCAP_PROTOCOL_PARSER_H
#define FAST_PCAP_PROTOCOL_PARSER_H

#include <cstddef>
#include <boost/cstdint.hpp>

namespace fast_pcap {

using boost::uint8_t;

class protocol_payload {
public:
    protocol_payload(const uint8_t *data, size_t size) : data_(data), size_(size) {}

    const uint8_t *data() const {
        return data_;
    }

    size_t size() const {
        return size_;
    }

private:
    const uint8_t *data_;
    std::size_t size_;
};

template<typename T>
class protocol_header {
public:
    typedef T header_type;

public:
    const static std::size_t header_size = sizeof(T);

public:
    protocol_header(const boost::uint8_t *buffer, size_t pos, size_t size) :
            buffer_(buffer),
            pos_(pos),
            size_(size) {
    }

public:
    template<typename U>
    protocol_header<U> unpack() {
        return protocol_header<U>(buffer_, pos_ + header_size, size_);
    }

    const T &header() const {
        return *this;
    }

    const T &operator*() const {
        return *reinterpret_cast<const T *>(buffer_ + pos_);
    }

    const T *operator->() const {
        return reinterpret_cast<const T *>(buffer_ + pos_);
    }

    protocol_payload payload() const {
        std::size_t payload_size = size_ > pos_ + header_size ? size_ - pos_ - header_size : 0;
        return protocol_payload(buffer_ + pos_ + header_size, payload_size);
    }

private:
    const uint8_t *buffer_;
    std::size_t pos_;
    std::size_t size_;
};

template<typename T>
protocol_header<T> parse_protocol(const boost::uint8_t *buffer, std::size_t size) {
    return protocol_header<T>(buffer, 0, size);
}

}


#endif //FAST_PCAP_PROTOCOL_PARSER_H
