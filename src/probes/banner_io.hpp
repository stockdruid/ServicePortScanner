#pragma once

// 공용 IO 헬퍼 — 타임아웃 동반 read_some, write_all.
// 모든 probe 가 동일한 로직을 쓰도록 추출.

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <chrono>
#include <cstddef>
#include <string>

namespace sps::probes::detail {

// timeout 동반 read. 받은 바이트를 banner 에 누적 (cap=kMaxBannerBytes).
// 반환: 성공 여부 (timeout 또는 closed 일 때 false 가능, banner 는 그대로).
boost::asio::awaitable<bool>
read_until_quiet(boost::asio::ip::tcp::socket& sock,
                 std::string& banner,
                 std::chrono::milliseconds timeout,
                 std::size_t cap);

// timeout 동반 write_all. 실패 시 false.
boost::asio::awaitable<bool>
write_all(boost::asio::ip::tcp::socket& sock,
          std::string_view payload,
          std::chrono::milliseconds timeout);

} // namespace sps::probes::detail
