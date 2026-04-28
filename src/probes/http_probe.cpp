#include "probes/banner_io.hpp"
#include "probes/probe.hpp"

#include <regex>

namespace sps::probes {

namespace {

constexpr std::string_view kHttpProbeRequest =
    "OPTIONS / HTTP/1.0\r\n"
    "User-Agent: spscan/0.1\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "\r\n";

class HttpProbe final : public Probe {
public:
    std::string_view name() const noexcept override { return "http"; }
    std::vector<std::uint16_t> hint_ports() const override {
        return {80, 8080, 8000, 8888};
    }

    boost::asio::awaitable<ProbeOutcome>
    identify(boost::asio::ip::tcp::socket& sock,
             std::chrono::milliseconds timeout) override {
        ProbeOutcome out;
        const bool wrote = co_await detail::write_all(sock, kHttpProbeRequest, timeout);
        if (!wrote) {
            co_return out;
        }
        std::string banner;
        const bool read = co_await detail::read_until_quiet(
            sock, banner, timeout, kMaxBannerBytes);
        if (!read || banner.empty()) {
            co_return out;
        }
        if (banner.rfind("HTTP/", 0) != 0) {
            co_return out;
        }
        out.matched = true;
        out.service = "http";
        out.banner = banner.substr(0, std::min<std::size_t>(banner.size(), 1024));

        // Server: nginx/1.18.0
        static const std::regex re(R"(Server:\s*([^\r\n]+))",
                                   std::regex::icase);
        std::smatch m;
        if (std::regex_search(banner, m, re) && m.size() >= 2) {
            out.version = m[1].str();
        }
        co_return out;
    }
};

} // namespace

ProbePtr make_http_probe() { return std::make_unique<HttpProbe>(); }

} // namespace sps::probes
