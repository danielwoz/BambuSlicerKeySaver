#pragma once
#include <string>
#include "bigint.h"
#include "reconstruct.h"

// ===========================================================================
// I/O helpers
// ===========================================================================
std::string slurp(const std::string& path);

bool write_pem_output(const std::string& path,
                      const DRecon& R, const bn::BigInt& N);
