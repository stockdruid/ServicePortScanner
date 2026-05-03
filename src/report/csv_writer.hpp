#pragma once

#include <string>
#include <vector>
#include "core/result.hpp"

namespace sps::report {

class CsvWriter {
public:
    static void write(const std::string& path,
                      const std::vector<sps::core::ScanResult>& results);
};

} // namespace sps::report
