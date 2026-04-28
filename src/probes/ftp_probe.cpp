#include "probes/banner_io.hpp"
#include "probes/probe.hpp"

#include <regex>

namespace sps::probes {

namespace {

class FtpProbe final : public Probe {
public:
    std::string_view name() const noexcept override { return "ftp"; }
    std::vector<std::uint16_t> hint_ports() const override { return {21}; }

    boost::asio::awaitable<ProbeOutcome>
    identify(boost::asio::ip::tcp::socket& sock,
             std::chrono::milliseconds timeout) override {
        ProbeOutcome out;
        std::string banner;
        const bool ok = co_await detail::read_until_quiet(
            sock, banner, timeout, kMaxBannerBytes);
        if (!ok || banner.empty()) {
            co_return out;
        }
        // FTP 응답: "220 <text>\r\n"
        if (banner.rfind("220", 0) != 0) {
            co_return out;
        }
        out.matched = true;
        out.service = "ftp";
        out.banner = banner;

        // 흔한 패턴: "vsFTPd 3.0.3", "(vsFTPd 3.0.3)", "ProFTPD 1.3.5e"
        static const std::regex re(R"(((?:vsFTPd|ProFTPD|FileZilla|Pure-FTPd)[\s/]?[\d.\w-]+))",
                                   std::regex::icase);
        std::smatch m;
        if (std::regex_search(banner, m, re) && m.size() >= 2) {
            out.version = m[1].str();
        }
        co_return out;
    }
};

} // namespace

ProbePtr make_ftp_probe() { return std::make_unique<FtpProbe>(); }

} // namespace sps::probes
