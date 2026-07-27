#include "output.h"
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

// The Linux build has a shared logging.h (clock_gettime + g_t0/g_verbose globals
// defined in its main). Those are absent in the Windows host, so map the log
// macros to plain stderr there; Linux keeps its timestamped logger.
#if defined(_WIN32)
  #define LOG_E(...) do { std::fprintf(stderr, "[ err ] " __VA_ARGS__); std::fprintf(stderr, "\n"); } while (0)
  #define LOG_W(...) do { std::fprintf(stderr, "[ warn] " __VA_ARGS__); std::fprintf(stderr, "\n"); } while (0)
  #define LOG_I(...) do { std::fprintf(stderr, "[ info] " __VA_ARGS__); std::fprintf(stderr, "\n"); } while (0)
#else
  #include "logging.h"
#endif

std::string slurp(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}

// ---------------------------------------------------------------------------
// PKCS#1 PEM output built directly from the recovered big integers -- no OpenSSL
// dependency, so the same code runs on Linux and Windows and emits a
// byte-identical, standard "RSA PRIVATE KEY" PEM (plus a SubjectPublicKeyInfo
// "PUBLIC KEY" pubkey).
// ---------------------------------------------------------------------------
namespace {

// Minimal big-endian magnitude of a BigInt (no leading zero, at least 1 byte).
std::vector<uint8_t> be_bytes(const bn::BigInt& x) {
    int bits = x.bit_length();
    size_t n = (bits + 7) / 8; if (n == 0) n = 1;
    std::vector<uint8_t> b(n);
    bn::to_bytes_be_fixed(x, b.data(), n);
    return b;
}

// Append a DER length (short form <128, else long form).
void der_len(std::vector<uint8_t>& out, size_t n) {
    if (n < 0x80) { out.push_back((uint8_t)n); return; }
    std::vector<uint8_t> tmp;
    while (n) { tmp.push_back((uint8_t)(n & 0xff)); n >>= 8; }
    out.push_back((uint8_t)(0x80 | tmp.size()));
    for (auto it = tmp.rbegin(); it != tmp.rend(); ++it) out.push_back(*it);
}

// DER INTEGER from a big-endian magnitude (prepends 0x00 if the top bit is set,
// keeping it a positive two's-complement value).
std::vector<uint8_t> der_int(const std::vector<uint8_t>& mag) {
    std::vector<uint8_t> body;
    if (mag[0] & 0x80) body.push_back(0x00);
    body.insert(body.end(), mag.begin(), mag.end());
    std::vector<uint8_t> v; v.push_back(0x02);
    der_len(v, body.size());
    v.insert(v.end(), body.begin(), body.end());
    return v;
}
std::vector<uint8_t> der_int(const bn::BigInt& x) { return der_int(be_bytes(x)); }

// Wrap `body` in a DER SEQUENCE.
std::vector<uint8_t> der_seq(const std::vector<uint8_t>& body) {
    std::vector<uint8_t> v; v.push_back(0x30);
    der_len(v, body.size());
    v.insert(v.end(), body.begin(), body.end());
    return v;
}

std::string base64(const std::vector<uint8_t>& in) {
    static const char* T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o; size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        uint32_t n = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        o += T[(n >> 18) & 63]; o += T[(n >> 12) & 63];
        o += T[(n >> 6) & 63];  o += T[n & 63];
    }
    if (in.size() - i == 1) {
        uint32_t n = (uint32_t)in[i] << 16;
        o += T[(n >> 18) & 63]; o += T[(n >> 12) & 63]; o += "==";
    } else if (in.size() - i == 2) {
        uint32_t n = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        o += T[(n >> 18) & 63]; o += T[(n >> 12) & 63]; o += T[(n >> 6) & 63]; o += "=";
    }
    return o;
}

std::string pem_wrap(const char* label, const std::vector<uint8_t>& der) {
    std::string b = base64(der), o;
    o += "-----BEGIN "; o += label; o += "-----\n";
    for (size_t i = 0; i < b.size(); i += 64) { o += b.substr(i, 64); o += "\n"; }
    o += "-----END "; o += label; o += "-----\n";
    return o;
}

bool write_file(const std::string& path, const std::string& data) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    if (!data.empty()) std::fwrite(data.data(), 1, data.size(), f);
    std::fclose(f);
    return true;
}

}  // namespace

bool write_pem_output(const std::string& path,
                      const DRecon& R, const bn::BigInt& N) {
    bn::BigInt e(uint32_t(65537));
    bn::BigInt qinv = bn::mod_inverse(R.q, R.p);   // coefficient = q^-1 mod p

    // RSAPrivateKey ::= SEQ { version(0), n, e, d, p, q, dp, dq, qinv }.
    std::vector<uint8_t> body;
    auto app = [&](const std::vector<uint8_t>& v) { body.insert(body.end(), v.begin(), v.end()); };
    app(der_int(std::vector<uint8_t>{0x00}));   // version 0
    app(der_int(N)); app(der_int(e)); app(der_int(R.d));
    app(der_int(R.p)); app(der_int(R.q));
    app(der_int(R.dp)); app(der_int(R.dq)); app(der_int(qinv));
    if (!write_file(path, pem_wrap("RSA PRIVATE KEY", der_seq(body)))) {
        LOG_E("write %s failed", path.c_str());
        return false;
    }

    // SubjectPublicKeyInfo "PUBLIC KEY": SEQ { rsaEncryption AlgId, BIT STRING {
    // RSAPublicKey ::= SEQ { n, e } } } -- matches the Linux tool's pubkey format.
    std::vector<uint8_t> rpk;
    { auto ni = der_int(N), ei = der_int(e);
      rpk.insert(rpk.end(), ni.begin(), ni.end());
      rpk.insert(rpk.end(), ei.begin(), ei.end()); }
    std::vector<uint8_t> rsa_pub = der_seq(rpk);
    std::vector<uint8_t> bitstr; bitstr.push_back(0x03);
    { std::vector<uint8_t> b; b.push_back(0x00);
      b.insert(b.end(), rsa_pub.begin(), rsa_pub.end());
      der_len(bitstr, b.size());
      bitstr.insert(bitstr.end(), b.begin(), b.end()); }
    static const uint8_t kRsaAlgId[] = {
        0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00};
    std::vector<uint8_t> spki(kRsaAlgId, kRsaAlgId + sizeof kRsaAlgId);
    spki.insert(spki.end(), bitstr.begin(), bitstr.end());

    auto slash = path.find_last_of("/\\");
    std::string dir = (slash == std::string::npos) ? "." : path.substr(0, slash);
    std::string pub = dir + "/slicer_pubkey.pem";
    if (write_file(pub, pem_wrap("PUBLIC KEY", der_seq(spki))))
        LOG_I("slicer_pubkey.pem written: %s", pub.c_str());
    else
        LOG_W("could not write slicer_pubkey.pem");
    return true;
}
