#include "probes/banner_io.hpp"
#include "probes/probe.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <memory>

namespace sps::probes {

namespace {

namespace asio = boost::asio;

struct SslDeleter {
    void operator()(SSL_CTX* p) const noexcept { if (p) SSL_CTX_free(p); }
};
struct SslSessionDeleter {
    void operator()(SSL* p) const noexcept { if (p) SSL_free(p); }
};
struct BioDeleter {
    void operator()(BIO* p) const noexcept { if (p) BIO_free(p); }
};

using SslCtxPtr = std::unique_ptr<SSL_CTX, SslDeleter>;
using SslPtr = std::unique_ptr<SSL, SslSessionDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

// 비동기 BIO pump: SSL_do_handshake 진행상황에 맞춰 socket I/O.
asio::awaitable<bool>
drive_handshake(asio::ip::tcp::socket& sock,
                SSL* ssl,
                BIO* rbio,
                BIO* wbio,
                std::chrono::milliseconds timeout) {
    char buf[4096];
    for (;;) {
        const int rc = SSL_do_handshake(ssl);
        if (rc == 1) {
            co_return true;
        }
        const int err = SSL_get_error(ssl, rc);

        // 보낼 바이트 비우기.
        for (;;) {
            const int pending = BIO_pending(wbio);
            if (pending <= 0) break;
            const int n = BIO_read(wbio, buf, std::min<int>(pending, sizeof(buf)));
            if (n <= 0) break;
            const bool ok = co_await detail::write_all(
                sock, std::string_view(buf, static_cast<std::size_t>(n)), timeout);
            if (!ok) co_return false;
        }

        if (err == SSL_ERROR_WANT_READ) {
            boost::system::error_code ec;
            const std::size_t n = co_await sock.async_read_some(
                asio::buffer(buf),
                asio::redirect_error(asio::use_awaitable, ec));
            if (ec || n == 0) co_return false;
            BIO_write(rbio, buf, static_cast<int>(n));
            continue;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        co_return false;
    }
}

class TlsProbe final : public Probe {
public:
    std::string_view name() const noexcept override { return "tls"; }
    std::vector<std::uint16_t> hint_ports() const override {
        return {443, 8443, 465, 993, 995};
    }

    boost::asio::awaitable<ProbeOutcome>
    identify(asio::ip::tcp::socket& sock,
             std::chrono::milliseconds timeout) override {
        ProbeOutcome out;

        SslCtxPtr ctx(SSL_CTX_new(TLS_client_method()));
        if (!ctx) co_return out;
        SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

        SslPtr ssl(SSL_new(ctx.get()));
        if (!ssl) co_return out;

        BIO* rbio = BIO_new(BIO_s_mem());
        BIO* wbio = BIO_new(BIO_s_mem());
        if (!rbio || !wbio) {
            if (rbio) BIO_free(rbio);
            if (wbio) BIO_free(wbio);
            co_return out;
        }
        SSL_set_bio(ssl.get(), rbio, wbio);  // SSL takes ownership.
        SSL_set_connect_state(ssl.get());

        const bool ok = co_await drive_handshake(sock, ssl.get(), rbio, wbio, timeout);
        if (!ok) co_return out;

        out.matched = true;
        out.service = "tls";
        const char* ver = SSL_get_version(ssl.get());
        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl.get());
        const char* cname = cipher ? SSL_CIPHER_get_name(cipher) : "unknown";
        out.version = (ver ? ver : "TLS") + std::string("/") + cname;
        out.banner = out.version;
        co_return out;
    }
};

} // namespace

ProbePtr make_tls_probe() { return std::make_unique<TlsProbe>(); }

} // namespace sps::probes
