// appcert_demo.cpp
//
// Thin demo over the appcert recovery library (appcert_recover.h): request the
// Bambu application certificate from the cloud REST API, decode the returned key
// blob, verify the recovered RSA private key against the certificate, and write
// app_key.pem. All the real work lives in bbl::appcert.
//
// Credentials come from BambuStudio's config by default (the network_engine
// config key is read from its standard save location); override with env vars:
//   BBL_TEST_TOKEN / BBL_TEST_UID  use this cloud token instead of the config
//   BBL_CONFIG_KEY                 the 16-char config key (else the saved file)
//   BBL_TEST_API                   API host (default https://api.bambulab.com)
//
//   appcert_demo <app_identity>          (or set BBL_APP_IDENTITY)
#include "appcert_recover.h"

#include <cstdio>
#include <cstdlib>
#include <string>

static const char* env_or(const char* k, const char* f) {
    const char* v = std::getenv(k);
    return (v && v[0]) ? v : f;
}

int main(int argc, char** argv) {
    std::string app_identity = (argc > 1) ? argv[1] : env_or("BBL_APP_IDENTITY", "");
    if (app_identity.empty()) {
        std::fprintf(stderr, "usage: %s <app_identity>   (or set BBL_APP_IDENTITY)\n", argv[0]);
        return 2;
    }
    const std::string api = env_or("BBL_TEST_API", "");

    std::printf("get_app_cert demo: fetch app cert (REST) -> decode key blob -> verify\n");
    std::printf("  app_identity = %s\n", app_identity.c_str());

    // A token in the environment overrides the config-based default (handy for
    // testing); otherwise recover_from_config() loads it from BambuStudio's config.
    bbl::appcert::Recovered r;
    const std::string token = env_or("BBL_TEST_TOKEN", "");
    if (!token.empty()) {
        r = bbl::appcert::recover(api.empty() ? "https://api.bambulab.com" : api,
                                  token, env_or("BBL_TEST_UID", ""), app_identity);
    } else {
        r = bbl::appcert::recover_from_config(app_identity, /*config_key*/std::string(),
                                              /*conf_path*/std::string(), api);
    }

    std::printf("  HTTP %ld  cert_id=%s  verified=%s\n",
                r.http_status, r.cert_id.c_str(), r.verified ? "YES" : "no");
    if (!r.ok) { std::fprintf(stderr, "FAILED: %s\n", r.error.c_str()); return 1; }

    const char* out_path = "app_key.pem";
    if (FILE* f = std::fopen(out_path, "wb")) {
        std::fwrite(r.app_key_pem.data(), 1, r.app_key_pem.size(), f);
        std::fclose(f);
    }
    std::printf("\n%s: fetched the app cert (HTTP 200), decoded the key blob, and %s.\n",
                r.verified ? "SUCCESS" : "PARTIAL",
                r.verified ? "verified the key against the certificate"
                           : "reconstructed the key (certificate not verified)");
    std::printf("         wrote %s (the recovered app RSA private key)\n", out_path);
    return r.ok ? 0 : 1;
}
