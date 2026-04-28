#include "probes/banner_io.hpp"
#include "probes/probe.hpp"

#include <regex>

namespace sps::probes {

namespace {

class SmtpProbe final : public Probe {
public:
    std::string_view name() const noexcept override { return "smtp"; }
    std::vector<std::uint16_t> hint_ports() const override { return {25, 465, 587}; }

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
        // SMTP greet: "220 <host> ESMTP <impl/version>\r\n"
        if (banner.rfind("220", 0) != 0) {
            co_return out;
        }
        out.matched = true;
        out.service = "smtp";
        out.banner = banner;

        static const std::regex re(R"(((?:Postfix|Sendmail|Exim|Microsoft ESMTP|qmail)[\s/]?[\d.\w-]*))",
                                   std::regex::icase);
        std::smatch m;
        if (std::regex_search(banner, m, re) && m.size() >= 2) {
            out.version = m[1].str();
        }
        co_return out;
    }
};

} // namespace

ProbePtr make_smtp_probe() { return std::make_unique<SmtpProbe>(); }

} // namespace sps::probes
