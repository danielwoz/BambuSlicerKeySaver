// appcert_recover.h
//
// Recover the Bambu "application" RSA private key from the cloud, with no
// proprietary plugin and no memory scanning:
//   1. get_app_cert REST call (obn::appcert::fetch) -> app cert + encrypted key blob
//   2. decrypt the blob (appcert_cipher.h: AES-256-CTR, swapped S-box, fixed key)
//   3. reconstruct the RSA private key and (optionally) verify it against the cert
//
// This is the default app-key path for BambuSlicerKeySaver. It runs AFTER the
// network_engine config key has been recovered (the config key decrypts the cloud
// token out of BambuNetworkEngine.conf); by default the config key is read from
// its standard save location (default_config_key_path()). The old memory-scanning
// extractor remains available as a backup for when no valid cloud token is present.
#pragma once

#include <string>

namespace bbl {
namespace appcert {

struct Recovered {
    bool         ok = false;
    long         http_status = 0;   // from the REST fetch (200 on success)
    std::string  error;
    std::string  cert_pem;          // the app certificate (from the cloud reply)
    std::string  cert_id;           // e.g. "4a63194e"
    std::string  crl;               // the app CRL, if returned
    std::string  app_key_pem;       // recovered RSA private key (PKCS#8 PEM)
    std::string  modulus_hex;       // recovered modulus N (uppercase hex)
    bool         verified = false;  // recovered N == the certificate's modulus
};

// Default file locations in the BambuStudio config dir.
std::string default_conf_path();         // %APPDATA%/BambuStudio/BambuNetworkEngine.conf
std::string default_config_key_path();   // %APPDATA%/BambuStudio/network_engine.key

// Read the 16-char network_engine config key. `path` empty -> default location.
// Accepts a find_config_key key file (the "ascii: <key>" line) or a file whose
// content is exactly the 16-char key. Returns "" if unavailable.
std::string load_config_key(const std::string& path = std::string());

// Decrypt BambuNetworkEngine.conf with `config_key` and pull out the cloud Bearer
// token + account uid. Returns false on failure.
bool load_cloud_token(const std::string& conf_path, const std::string& config_key,
                      std::string& token, std::string& uid);

// Decode a raw get_app_cert "key" blob (base64) into the app RSA private key.
// If `cert_pem` is given, verifies the recovered modulus against it. No network.
Recovered decode_key_blob(const std::string& key_blob_b64,
                          const std::string& cert_pem = std::string());

// Full online recovery: fetch the app cert (REST) then decode the key blob.
Recovered recover(const std::string& api_host,
                  const std::string& access_token,
                  const std::string& user_id,
                  const std::string& app_identity);

// Convenience / default path: load the config key (from `config_key`, else the
// BBL_CONFIG_KEY env var, else default_config_key_path()), decrypt the cloud token
// out of the conf (default_conf_path() unless `conf_path` given), and run recover().
// `api_host` empty -> https://api.bambulab.com.
Recovered recover_from_config(const std::string& app_identity,
                              const std::string& config_key = std::string(),
                              const std::string& conf_path  = std::string(),
                              const std::string& api_host   = std::string());

}  // namespace appcert
}  // namespace bbl
