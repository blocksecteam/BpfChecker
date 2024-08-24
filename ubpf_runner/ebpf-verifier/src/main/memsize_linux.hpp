// SPDX-License-Identifier: CC-BY-SA-2.5
#pragma once
// from https://stackoverflow.com/a/671389/2289509
// see https://stackoverflow.com/help/licensing

#include <fstream>
#include <ios>
#include <iostream>
#include <string>
#include <unistd.h>

inline long resident_set_size_kb() {
    std::string _{};
    unsigned long __{};
    long rss = 0;
    {
        std::ifstream stat_stream("/proc/self/stat", std::ios_base::in);
        stat_stream >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >> _ >>
            _ >> _ >> _ >> __ >> rss; // don't care about the rest
    }

    long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024; // in case x86-64 is configured to use 2MB pages
    return rss * page_size_kb;
}
