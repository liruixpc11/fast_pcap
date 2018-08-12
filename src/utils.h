//
// Created by lirui on 2018/8/10.
//

#ifndef FAST_PCAP_UTILS_H
#define FAST_PCAP_UTILS_H

#include <ctime>
#include <functional>
#include <iostream>
#include <boost/cstdint.hpp>

#ifdef WINDOWS
#include <direct.h>

namespace fast_pcap {
inline std::string get_current_dir() {
    char current_dir[FILENAME_MAX];
    _getcwd(current_dir, sizeof(current_dir));
    return std::string(current_dir);
}
}
#else

#include <unistd.h>

namespace fast_pcap {
inline std::string get_current_dir() {
    char current_dir[FILENAME_MAX];
    getcwd(current_dir, sizeof(current_dir));
    return std::string(current_dir);
}

}
#endif

namespace fast_pcap {

inline boost::uint16_t adjust_endian(boost::uint16_t n) {
    __asm__("xchgb %b0,%h0"        /* swap bytes		*/
    : "=Q" (n)
    :  "0" (n));
    return n;
}

inline boost::uint16_t adjust_endian(boost::uint16_t n, bool little_endian) {
    if (!little_endian) {
        __asm__("xchgb %b0,%h0"        /* swap bytes		*/
        : "=Q" (n)
        :  "0" (n));
    }

    return n;
}

inline boost::uint32_t adjust_endian(boost::uint32_t n) {
    __asm__("bswap %0" : "=r" (n) : "0" (n));
    return n;
}

inline boost::uint32_t adjust_endian(boost::uint32_t n, bool little_endian) {
    if (!little_endian) {
        __asm__("bswap %0" : "=r" (n) : "0" (n));
    }

    return n;
}

inline void time_run(std::function<void()> function) {
    std::clock_t begin_time = std::clock();
    function();
    std::clock_t end_time = std::clock();
    std::cout << "COST " << ((end_time - begin_time) / static_cast<double>(CLOCKS_PER_SEC)) << "s" << std::endl;
}

inline std::string ipv4_str(uint32_t x) {
    char buf[16];
    snprintf(buf, sizeof buf, "%u.%u.%u.%u",
             (x) % 0x100,
             (x / 0x100u) % 0x100,
             (x / 0x10000u) % 0x100,
             (x / 0x1000000u) % 0x100);

    return std::string(buf);
}

}

#endif //FAST_PCAP_UTILS_H
