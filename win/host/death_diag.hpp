#pragma once
// Diagnostic for when the plugin exits mid-capture: log why (crash, deliberate
// process-exit, or hang). Install once, early (before LoadLibrary of the plugin).
namespace bbl { void install_death_diag(); }
