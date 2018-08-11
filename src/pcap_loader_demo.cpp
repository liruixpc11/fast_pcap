//
// Created by lirui on 2018/8/10.
//

#include <iostream>
#include <ctime>

#include "pcap_loader.h"
#include "utils.h"

using namespace fast_pcap;

void demo() {
//    pcap_file_ptr pcap_file = load_from_pcap_file("../data/LLS_DDOS_1.0-dmz.dump");
    pcap_file_ptr pcap_file = load_from_pcap_file("../data/traceroute.pcap");
//    pcap_file_ptr pcap_file = load_from_pcap_file("E:/datasets/iscxIDS2012/testbed-12jun.pcap");
//    pcap_file_ptr pcap_file = load_from_pcap_file("E:/datasets/iscxIDS2012/testbed-16jun.pcap");

    auto end = pcap_file->end();
    uint64_t total_length = 0;
    for (auto itr = pcap_file->begin(); itr != end; ++itr) {
        total_length += itr->length();
    }

    std::cout << total_length << std::endl;
}

int main() {
    time_run(demo);
}
