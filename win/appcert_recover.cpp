// appcert_recover.cpp -- see appcert_recover.h.
#include "appcert_recover.h"

#include "appcert_cipher.h"
#include "obn/app_cert.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace bbl {
namespace appcert {
namespace {

std::string env_or(const char* k, const char* fallback) {
    const char* v = std::getenv(k);
    return (v && v[0]) ? std::string(v) : std::string(fallback);
}

bool read_file(const std::string& path, std::string& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    char b[8192]; size_t n;
    while ((n = std::fread(b, 1, sizeof b, f)) > 0) out.append(b, n);
    std::fclose(f);
    return true;
}

// base64 decode accepting both standard (+/) and URL-safe (-_) alphabets.
std::vector<uint8_t> b64decode(const std::string& in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    int buf = 0, bits = 0;
    for (char c : in) {
        int v = val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((uint8_t)((buf >> bits) & 0xFF)); }
    }
    return out;
}

// AES-128-ECB decrypt, no padding (the plugin space-pads the config), via OpenSSL.
std::string aes128_ecb_decrypt(const std::string& ct, const std::string& key) {
    std::string out;
    if (key.size() != 16 || ct.empty() || (ct.size() % 16) != 0) return out;
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return out;
    out.resize(ct.size());
    int len = 0, total = 0;
    if (EVP_DecryptInit_ex(c, EVP_aes_128_ecb(), nullptr, (const uint8_t*)key.data(), nullptr) == 1) {
        EVP_CIPHER_CTX_set_padding(c, 0);
        if (EVP_DecryptUpdate(c, (uint8_t*)out.data(), &len, (const uint8_t*)ct.data(), (int)ct.size()) == 1) {
            total = len;
            if (EVP_DecryptFinal_ex(c, (uint8_t*)out.data() + total, &len) == 1) { total += len; out.resize(total); }
            else out.clear();
        } else out.clear();
    } else out.clear();
    EVP_CIPHER_CTX_free(c);
    return out;
}

// Serialize an EVP_PKEY private key to a PKCS#8 PEM string.
std::string pkey_to_pem(EVP_PKEY* pkey) {
    if (!pkey) return {};
    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem) return {};
    std::string out;
    if (PEM_write_bio_PrivateKey(mem, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
        char* data = nullptr;
        long n = BIO_get_mem_data(mem, &data);
        if (data && n > 0) out.assign(data, (size_t)n);
    }
    BIO_free(mem);
    return out;
}

}  // namespace

std::string default_conf_path() {
    return env_or("APPDATA", "") + "\\BambuStudio\\BambuNetworkEngine.conf";
}

std::string default_config_key_path() {
    return env_or("APPDATA", "") + "\\BambuStudio\\network_engine.key";
}

std::string load_config_key(const std::string& path) {
    std::string p = path.empty() ? default_config_key_path() : path;
    std::string s;
    if (!read_file(p, s)) return "";
    // find_config_key key-file format: a line "ascii: <16 chars>".
    size_t a = s.find("ascii:");
    if (a != std::string::npos) {
        a = s.find_first_not_of(" \t", a + 6);
        if (a == std::string::npos) return "";
        size_t e = s.find_first_of("\r\n", a);
        std::string k = s.substr(a, (e == std::string::npos ? s.size() : e) - a);
        return k.size() == 16 ? k : "";
    }
    // Otherwise accept a file that is exactly the 16-char key (± trailing whitespace).
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s.size() == 16 ? s : "";
}

bool load_cloud_token(const std::string& conf_path, const std::string& config_key,
                      std::string& token, std::string& uid) {
    std::string conf;
    if (!read_file(conf_path, conf)) return false;
    std::string pt = aes128_ecb_decrypt(conf, config_key);
    // The decrypted config is JSON, space-padded to the block size; parse the
    // object between the outer braces.
    size_t a = pt.find('{'), b = pt.rfind('}');
    if (a == std::string::npos || b == std::string::npos || b < a) return false;
    auto root = obn::json::parse(pt.substr(a, b - a + 1));
    if (!root) return false;
    // The cloud login lives under "user"; fall back to a top-level "token".
    obn::json::Value tv = root->find("user.token");
    if (!tv.is_string() || tv.as_string().empty()) tv = root->find("token");
    token = tv.as_string();
    obn::json::Value u = root->find("user.user_id");
    if (u.is_null()) u = root->find("user_id");
    uid = u.is_string() ? u.as_string()
        : u.is_number() ? std::to_string(u.as_int()) : std::string();
    return !token.empty();
}

Recovered decode_key_blob(const std::string& key_blob_b64, const std::string& cert_pem) {
    Recovered r;
    std::vector<uint8_t> blob = b64decode(key_blob_b64);
    if (blob.size() < 32 + 288) { r.error = "key blob too short"; return r; }

    uint32_t ctlen = blob[28] | (blob[29] << 8) | (blob[30] << 16) | ((uint32_t)blob[31] << 24);
    if (32 + ctlen > blob.size()) ctlen = (uint32_t)blob.size() - 32;
    std::vector<uint8_t> pt(ctlen);
    ::appcert::ctr_xor(::appcert::APPCERT_KEY, blob.data(), blob.data() + 32, ctlen, pt.data());
    if (!(pt[0] == 0x59 && pt[1] == 0x45 && pt[2] == 0x4b && pt[3] == 0x53)) {
        r.error = "SKEY magic missing (decode failed)"; return r;
    }

    // SKEY: 32-byte header, then p|q|dp|dq|qinv (128 bytes each, big-endian).
    const int H = 32, L = 128;
    BIGNUM* p    = BN_bin2bn(pt.data() + H + 0 * L, L, nullptr);
    BIGNUM* q    = BN_bin2bn(pt.data() + H + 1 * L, L, nullptr);
    BIGNUM* dp   = BN_bin2bn(pt.data() + H + 2 * L, L, nullptr);
    BIGNUM* dq   = BN_bin2bn(pt.data() + H + 3 * L, L, nullptr);
    BIGNUM* qinv = BN_bin2bn(pt.data() + H + 4 * L, L, nullptr);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* n = BN_new();  BN_mul(n, p, q, ctx);
    BIGNUM* e = BN_new();  BN_set_word(e, 65537);
    BIGNUM* p1 = BN_dup(p); BN_sub_word(p1, 1);
    BIGNUM* q1 = BN_dup(q); BN_sub_word(q1, 1);
    BIGNUM* g = BN_new();   BN_gcd(g, p1, q1, ctx);
    BIGNUM* lcm = BN_new(); BN_mul(lcm, p1, q1, ctx); BN_div(lcm, nullptr, lcm, g, ctx);
    BIGNUM* d = BN_new();   BN_mod_inverse(d, e, lcm, ctx);

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qinv);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY* pkey = nullptr;
    if (pctx && EVP_PKEY_fromdata_init(pctx) == 1)
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params);

    r.app_key_pem = pkey_to_pem(pkey);
    if (char* hx = BN_bn2hex(n)) { r.modulus_hex = hx; OPENSSL_free(hx); }

    if (!cert_pem.empty()) {
        BIO* cbio = BIO_new_mem_buf(cert_pem.data(), (int)cert_pem.size());
        X509* x = cbio ? PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr) : nullptr;
        EVP_PKEY* certpub = x ? X509_get_pubkey(x) : nullptr;
        BIGNUM* cert_n = nullptr;
        if (certpub) EVP_PKEY_get_bn_param(certpub, OSSL_PKEY_PARAM_RSA_N, &cert_n);
        r.verified = cert_n && BN_cmp(n, cert_n) == 0;
        if (cert_n) BN_free(cert_n);
        if (certpub) EVP_PKEY_free(certpub);
        if (x) X509_free(x);
        if (cbio) BIO_free(cbio);
    }

    r.ok = !r.app_key_pem.empty();
    if (!r.ok && r.error.empty()) r.error = "RSA key reconstruction failed";

    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (params) OSSL_PARAM_free(params);
    if (bld) OSSL_PARAM_BLD_free(bld);
    BN_free(p); BN_free(q); BN_free(dp); BN_free(dq); BN_free(qinv);
    BN_free(n); BN_free(e); BN_free(d);
    BN_free(p1); BN_free(q1); BN_free(g); BN_free(lcm);
    BN_CTX_free(ctx);
    return r;
}

Recovered recover(const std::string& api_host, const std::string& access_token,
                  const std::string& user_id, const std::string& app_identity) {
    Recovered r;
    if (access_token.empty() || app_identity.empty()) { r.error = "missing token or app_identity"; return r; }

    obn::http::global_init();
    auto fr = obn::appcert::fetch(api_host, access_token, user_id, app_identity);
    r.http_status = fr.http_status;
    if (!fr.ok || fr.http_status != 200) {
        r.error = fr.error.empty() ? ("http " + std::to_string(fr.http_status)) : fr.error;
        return r;
    }
    r.cert_pem = fr.cert_pem;
    r.cert_id  = fr.cert_id;
    r.crl      = fr.crl;

    Recovered dec = decode_key_blob(fr.key_blob_b64, fr.cert_pem);
    r.app_key_pem = dec.app_key_pem;
    r.modulus_hex = dec.modulus_hex;
    r.verified    = dec.verified;
    r.ok          = dec.ok;
    if (!dec.ok) r.error = dec.error;
    return r;
}

Recovered recover_from_config(const std::string& app_identity, const std::string& config_key,
                              const std::string& conf_path, const std::string& api_host) {
    Recovered r;
    // config key: explicit arg > BBL_CONFIG_KEY env > default save location.
    std::string ck = config_key;
    if (ck.empty()) ck = env_or("BBL_CONFIG_KEY", "");
    if (ck.size() != 16) ck = load_config_key();
    if (ck.size() != 16) {
        r.error = "network_engine config key not found; recover it first "
                  "(--find-config-key) or pass it explicitly. Looked at " + default_config_key_path();
        return r;
    }
    const std::string conf = conf_path.empty() ? default_conf_path() : conf_path;
    const std::string api  = api_host.empty() ? std::string("https://api.bambulab.com") : api_host;

    std::string token, uid;
    if (!load_cloud_token(conf, ck, token, uid)) {
        r.error = "could not read a cloud token from " + conf + " (is BambuStudio logged in?)";
        return r;
    }
    return recover(api, token, uid, app_identity);
}

}  // namespace appcert
}  // namespace bbl
