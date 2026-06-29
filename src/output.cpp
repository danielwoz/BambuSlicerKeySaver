#include "output.h"
#include "logging.h"
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

std::string slurp(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}

bool write_pem_output(const std::string& path,
                      const DRecon& R, const bn::BigInt& N) {
    auto bn_from_bigint = [](const bn::BigInt& x) -> BIGNUM* {
        BIGNUM* b = nullptr;
        std::string h = bn::to_hex_str(x, false);
        BN_hex2bn(&b, h.c_str());
        return b;
    };

    RSA* rsa = RSA_new();
    if (!rsa) { LOG_E("RSA_new failed"); return false; }

    BIGNUM* n  = bn_from_bigint(N);
    BIGNUM* e  = BN_new();
    BIGNUM* d  = bn_from_bigint(R.d);
    BIGNUM* p  = bn_from_bigint(R.p);
    BIGNUM* q  = bn_from_bigint(R.q);
    BIGNUM* dp = bn_from_bigint(R.dp);
    BIGNUM* dq = bn_from_bigint(R.dq);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* qi  = BN_new();

    if (!n || !e || !d || !p || !q || !dp || !dq || !ctx || !qi) {
        LOG_E("OpenSSL BIGNUM allocation failed");
        BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q);
        BN_free(dp); BN_free(dq); BN_free(qi); BN_CTX_free(ctx);
        RSA_free(rsa);
        return false;
    }

    BN_set_word(e, 65537);
    if (!BN_mod_inverse(qi, q, p, ctx)) {
        LOG_E("BN_mod_inverse failed");
        BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q);
        BN_free(dp); BN_free(dq); BN_free(qi); BN_CTX_free(ctx);
        RSA_free(rsa);
        return false;
    }
    BN_CTX_free(ctx);

    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, dp, dq, qi);

    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_E("open(%s): %s", path.c_str(), strerror(errno));
        RSA_free(rsa);
        return false;
    }
    FILE* f = fdopen(fd, "w");
    if (!f) { close(fd); RSA_free(rsa); return false; }

    int ok = PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    if (!ok) { RSA_free(rsa); LOG_E("PEM_write_RSAPrivateKey failed"); return false; }

    auto slash = path.rfind('/');
    std::string dir = (slash == std::string::npos) ? "." : path.substr(0, slash);

    std::string pubkey_path = dir + "/slicer_pubkey.pem";
    FILE* pf = fopen(pubkey_path.c_str(), "w");
    if (pf) {
        PEM_write_RSA_PUBKEY(pf, rsa);
        fclose(pf);
        LOG_I("slicer_pubkey.pem written: %s", pubkey_path.c_str());
    } else {
        LOG_W("could not write slicer_pubkey.pem: %s", strerror(errno));
    }

    RSA_free(rsa);
    return true;
}
