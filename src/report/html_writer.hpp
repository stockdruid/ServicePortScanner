#pragma once

#include <string>
#include <vector>
#include "core/result.hpp"

namespace sps::report {

class HtmlWriter {
public:
    static void write(const std::string& path,
                      const std::vector<sps::core::ScanResult>& results);
};

} // namespace sps::report
