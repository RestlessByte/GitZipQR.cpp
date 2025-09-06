#pragma once
/*
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃ GitZipQR-CPP – Central configuration                               ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  • All parameters are configured here — no environment variables required.
  • You can adjust QR code settings, default password, and console options.
*/

namespace gzqr_config {

// ── Project / branding ────────────────────────────────────────────────
inline constexpr const char* kProjectName    = "GitZipQR-CPP";
inline constexpr const char* kProjectVersion = "4.1-cpp-inline";

// ── Support / footer (optional) ───────────────────────────────────────
// These values are only used if you want to embed support/watermark data
// in generated QR codes or logs. Safe to ignore if not needed.
inline constexpr bool        kShowSupportFooter = true;
inline constexpr const char* kSupportAddressETH = "0xa8b3A40008EDF9AF21D981Dc3A52aa0ed1cA88fD";
inline constexpr bool        kShowPinAndDcodes  = true;

// ── QR layout defaults ────────────────────────────────────────────────
// Default parameters for QR generation (can be tuned per project needs).
inline constexpr char kDefaultQRECL     = 'L';   // Error correction: L=lowest (max capacity)
inline constexpr int  kDefaultQRVersion = 40;    // Max QR size (v40 = 177×177 modules)
inline constexpr int  kDefaultQRMargin  = 1;     // Margin (quiet zone) around QR
inline constexpr int  kDefaultQRScale   = 8;     // PNG scaling factor (pixels per module)

// ── Password config ───────────────────────────────────────────────────
// WARNING: Storing passwords in source code is insecure!
// This is provided only as a fallback for testing purposes.
// Always override via the GZQR_PASS environment variable in production.
inline constexpr const char* kDefaultPassword = "SuperSecret123"; 

// ── Misc console cosmetics ────────────────────────────────────────────
inline constexpr bool kPrintProgressCounters = true; // Show per-chunk progress logs

} // namespace gzqr_config
