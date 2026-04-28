#include "core/scanner.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace sps::core {

namespace {

namespace asio = boost::asio;
using boost::asio::ip::tcp;
using namespace boost::asio::experimental::awaitable_operators;

asio::awaitable<void> sleep_for(asio::any_io_executor exec,
                                std::chrono::milliseconds ms) {
    asio::steady_timer t(exec);
    t.expires_after(ms);
    boost::system::error_code ec;
    co_await t.async_wait(asio::redirect_error(asio::use_awaitable, ec));
}

asio::awaitable<std::pair<bool, tcp::socket>>
do_connect(asio::any_io_executor exec, const ScanRequest& req) {
    tcp::resolver resolver(exec);
    boost::system::error_code ec;
    auto results = co_await resolver.async_resolve(
        req.host, std::to_string(req.port),
        asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return std::make_pair(false, tcp::socket(exec));
    }

    tcp::socket sock(exec);
    co_await asio::async_connect(
        sock, results,
        asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        co_return std::make_pair(false, tcp::socket(exec));
    }
    co_return std::make_pair(true, std::move(sock));
}

ScanResult make_result(const ScanRequest& req, PortState st) {
    ScanResult r;
    r.host = req.host;
    r.port = req.port;
    r.state = st;
    r.completed_at = std::chrono::steady_clock::now();
    return r;
}

} // namespace

asio::awaitable<ScanResult>
connect_scan(asio::any_io_executor exec, ScanRequest req) {
    // connect vs timeout 경쟁.
    auto connect_op = do_connect(exec, req);
    auto timeout_op = sleep_for(exec, req.timeout);

    auto which = co_await (std::move(connect_op) || std::move(timeout_op));
    if (which.index() == 1) {
        co_return make_result(req, PortState::Filtered);
    }
    auto [ok, sock] = std::get<0>(std::move(which));
    if (!ok) {
        co_return make_result(req, PortState::Closed);
    }
    boost::system::error_code ec;
    sock.shutdown(tcp::socket::shutdown_both, ec);
    sock.close(ec);
    co_return make_result(req, PortState::Open);
}

} // namespace sps::core
