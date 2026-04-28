#include "probes/banner_io.hpp"
#include "probes/probe.hpp"

#include <regex>

namespace sps::probes {

namespace {

class SshProbe final : public Probe {
public:
    std::string_view name() const noexcept override { return "ssh"; }
    std::vector<std::uint16_t> hint_ports() const override { return {22, 2222}; }

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
        // 형식: "SSH-<protover>-<softver>\r\n"
        if (banner.rfind("SSH-", 0) != 0) {
            co_return out;
        }
        out.matched = true;
        out.service = "ssh";
        out.banner = banner;

        static const std::regex re(R"(^SSH-\d+\.\d+-([^\r\n]+))");
        std::smatch m;
        if (std::regex_search(banner, m, re) && m.size() >= 2) {
            out.version = m[1].str();
        }
        co_return out;
    }
};

} // namespace

ProbePtr make_ssh_probe() { return std::make_unique<SshProbe>(); }

} // namespace sps::probes
