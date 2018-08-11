//
// Created by lirui on 2018/8/10.
//

#ifndef FAST_PCAP_PCAP_LOADER_H
#define FAST_PCAP_PCAP_LOADER_H

#include <iterator>
#include <string>
#include <memory>
#include <boost/cstdint.hpp>
#include <boost/noncopyable.hpp>
#include <utility>

namespace fast_pcap {

class pcap_frame {
public:
    pcap_frame(size_t length, uint32_t seconds, uint32_t micro_seconds) :
            length_(length),
            seconds(seconds),
            micro_seconds(micro_seconds) {
        content_ = new uint8_t[length];
    }

    ~pcap_frame() {
        delete[] content_;
    }

    pcap_frame(const pcap_frame &other) = delete;
    pcap_frame &operator=(const pcap_frame &other) = delete;

public:
    inline boost::uint8_t *buffer() {
        return content_;
    }

    inline const boost::uint8_t *content() const {
        return content_;
    }

    inline std::size_t length() const {
        return length_;
    }

private:
    boost::uint8_t *content_;
    std::size_t length_;

    uint32_t seconds;
    uint32_t micro_seconds;
};

typedef std::shared_ptr<pcap_frame> pcap_frame_ptr;

class pcap_file;

class pcap_iterator {
public:
    typedef pcap_iterator self_type;
    typedef pcap_frame_ptr value_type;
    typedef pcap_frame_ptr &reference;
    typedef pcap_frame_ptr pointer;
    typedef std::input_iterator_tag iterator_category;

public:
    pcap_iterator() = default;

    explicit pcap_iterator(const pcap_file *file);

public:
    self_type operator++();

    const reference operator*() {
        return frame_;
    }

    const pointer operator->(){
        return frame_;
    }

    bool operator==(const self_type &other);

    bool operator!=(const self_type &other);

public:
    const pcap_file *file_;
    mutable pcap_frame_ptr frame_;
};

struct pcap_file_impl;

class pcap_file {
public:
    typedef pcap_iterator const_iterator;

public:
    pcap_file(bool little_endian_, int version_major_, int version_minor_, pcap_file_impl *impl)
            : little_endian_(little_endian_),
              version_major_(version_major_),
              version_minor_(version_minor_),
              impl_(impl) {
    }

    virtual ~pcap_file();

public:
    const_iterator begin() const;

    const_iterator end() const;

public:
    bool little_endian() const {
        return little_endian_;
    }

    int version_major() const {
        return version_major_;
    }

    int version_minor() const {
        return version_minor_;
    }

    pcap_file_impl *impl() const {
        return impl_;
    }

private:
    bool little_endian_;
    int version_major_;
    int version_minor_;

    pcap_file_impl *impl_;
};

typedef std::shared_ptr<pcap_file> pcap_file_ptr;

class pcap_load_error : public std::exception {
public:
    explicit pcap_load_error(std::string reason)
            : reason_(std::move(reason)) {
    }

private:
    std::string reason_;
};

pcap_file_ptr load_from_pcap_file(const std::string &file_name);

}


#endif //FAST_PCAP_PCAP_LOADER_H
