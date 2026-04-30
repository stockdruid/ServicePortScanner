#include "fp/ja4_server.hpp"
#include "fp/ja4_x509.hpp"
#include "probes/banner_io.hpp"
#include "probes/probe.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <cstdint>
#include <memory>
#include <vector>

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

// ServerHello 핸드셰이크 메시지 캡처용 — JA4S 계산에 필요.
struct TlsCapture {
    std::vector<std::uint8_t> server_hello;  // 4-byte handshake header 포함.
};

extern "C" void msg_capture_cb(int write_p,
                                int /*version*/,
                                int content_type,
                                const void* buf,
                                size_t len,
                                SSL* /*ssl*/,
                                void* arg) {
    if (write_p != 0) return;       // 받은 메시지만.
    if (content_type != 22) return; // handshake.
    if (!buf || len < 1) return;
    const auto* p = static_cast<const std::uint8_t*>(buf);
    if (p[0] != 0x02) return;       // ServerHello 만 (handshake type 2).
    auto* cap = static_cast<TlsCapture*>(arg);
    cap->server_hello.assign(p, p + len);
}

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

void fill_fingerprints(SSL* ssl, const TlsCapture& cap, ProbeOutcome& out) {
    // JA4S: ServerHello 바이트에서 cipher_id / extension_types 파싱 후
    //        SSL API 로 ALPN/cipher 보강.
    if (cap.server_hello.size() > 4) {
        // 4-byte handshake header (type=2, len=3 bytes) 건너뛰기.
        sps::fp::Ja4SInput in = sps::fp::parse_server_hello(
            cap.server_hello.data() + 4,
            cap.server_hello.size() - 4);

        if (auto* cipher = SSL_get_current_cipher(ssl)) {
            const auto id = SSL_CIPHER_get_protocol_id(cipher);
            in.cipher_id = static_cast<std::uint16_t>(id);
        }
        const unsigned char* alpn_data = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(ssl, &alpn_data, &alpn_len);
        if (alpn_data && alpn_len > 0) {
            in.alpn.assign(reinterpret_cast<const char*>(alpn_data),
                           static_cast<std::size_t>(alpn_len));
        }
        out.ja4s = sps::fp::compute_ja4s(in);
    }

    // JA4X: 서버 인증서 OID 추출.
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    X509* peer = SSL_get1_peer_certificate(ssl);
#else
    X509* peer = SSL_get_peer_certificate(ssl);
#endif
    if (peer) {
        auto x = sps::fp::extract_ja4x_input(peer);
        out.ja4x = sps::fp::compute_ja4x(x);
        X509_free(peer);
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

        // ALPN 광고 — h2 + http/1.1. 서버가 ALPN 답하면 JA4S 에 반영.
        constexpr unsigned char kAlpn[] = {
            0x02, 'h', '2',
            0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        SSL_set_alpn_protos(ssl.get(), kAlpn, sizeof(kAlpn));

        TlsCapture cap;
        SSL_set_msg_callback(ssl.get(), msg_capture_cb);
        SSL_set_msg_callback_arg(ssl.get(), &cap);

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

        fill_fingerprints(ssl.get(), cap, out);

        co_return out;
    }
};

} // namespace

ProbePtr make_tls_probe() { return std::make_unique<TlsProbe>(); }

} // namespace sps::probes
