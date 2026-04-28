#include "probes/banner_io.hpp"

#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <array>

namespace sps::probes::detail {

namespace asio = boost::asio;
using boost::asio::ip::tcp;
using namespace boost::asio::experimental::awaitable_operators;

namespace {

asio::awaitable<void> sleep_for(asio::any_io_executor exec,
                                std::chrono::milliseconds ms) {
    asio::steady_timer t(exec);
    t.expires_after(ms);
    boost::system::error_code ec;
    co_await t.async_wait(asio::redirect_error(asio::use_awaitable, ec));
}

} // namespace

asio::awaitable<bool>
read_until_quiet(tcp::socket& sock,
                 std::string& banner,
                 std::chrono::milliseconds timeout,
                 std::size_t cap) {
    std::array<char, 1024> buf{};
    auto read_op = [&]() -> asio::awaitable<bool> {
        for (;;) {
            boost::system::error_code ec;
            std::size_t n = co_await sock.async_read_some(
                asio::buffer(buf),
                asio::redirect_error(asio::use_awaitable, ec));
            if (ec || n == 0) {
                co_return !banner.empty();
            }
            const std::size_t room = (banner.size() < cap)
                ? (cap - banner.size())
                : 0;
            if (room == 0) {
                co_return true;
            }
            banner.append(buf.data(), std::min(n, room));
            if (banner.size() >= cap) {
                co_return true;
            }
        }
    };

    auto which = co_await (read_op() || sleep_for(sock.get_executor(), timeout));
    if (which.index() == 1) {
        co_return !banner.empty();
    }
    co_return std::get<0>(which);
}

asio::awaitable<bool>
write_all(tcp::socket& sock,
          std::string_view payload,
          std::chrono::milliseconds timeout) {
    auto write_op = [&]() -> asio::awaitable<bool> {
        boost::system::error_code ec;
        co_await asio::async_write(
            sock, asio::buffer(payload),
            asio::redirect_error(asio::use_awaitable, ec));
        co_return !ec;
    };

    auto which = co_await (write_op() || sleep_for(sock.get_executor(), timeout));
    if (which.index() == 1) {
        co_return false;
    }
    co_return std::get<0>(which);
}

} // namespace sps::probes::detail
