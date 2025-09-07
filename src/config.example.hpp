#ifndef GITZIPQR_CONFIG_H
#define GITZIPQR_CONFIG_H

#include <iostream>
#include <chrono>
#include <ctime>

/*
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃ GitZipQR.cpp – Central configuration                               ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  • All parameters are configured here — no environment variables required.
  • You can adjust QR code settings, default password, and console options.
*/

namespace gzqr_config
{

  // ── Project / branding ────────────────────────────────────────────────
  inline constexpr const char *kProjectName = "GitZipQR.cpp";
  inline constexpr const char *kProjectVersion = "4.1-.cpp.inline";

  // ── Support / footer (optional) ───────────────────────────────────────
  // These values are only used if you want to embed support/watermark data
  // in generated QR codes or logs. Safe to ignore if not needed.
  inline constexpr bool kShowSupportFooter = true;
  inline constexpr const char *kSupportAddressETH = "0xa8b3A40008EDF9AF21D981Dc3A52aa0ed1cA88fD";
  inline constexpr bool kShowPinAndDcodes = true;
  inline constexpr bool kRandomPinAndDcodess = false; // TODO: random pin and dcodes (!stric:memorize them, or you'll lose your data!)

  // ── QR layout defaults ────────────────────────────────────────────────
  // Default parameters for QR generation (can be tuned per project needs).
  inline constexpr char kDefaultQRECL = 'L';   // Error correction: L=lowest (max capacity)
  inline constexpr int kDefaultQRVersion = 40; // Max QR size (v40 = 177×177 modules)
  inline constexpr int kDefaultQRMargin = 1;   // Margin (quiet zone) around QR
  inline constexpr int kDefaultQRScale = 8;    // PNG scaling factor (pixels per module)

  // ── Password config ───────────────────────────────────────────────────
  // WARNING: Storing passwords in source code is insecure!
  // This is provided only as a fallback for testing purposes.
  // Always override via the GZQR_PASS environment variable in production.

  // Function to generate default password with timestamp (can remove)
  inline std::string getDefaultPassword()
  {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    char time_str[100];

    std::strftime(time_str, sizeof(time_str), "%d%m%Y", std::localtime(&now_time));

    char password[150];
    std::snprintf(password, sizeof(password), "GitZipQR.cpp#Security %s", time_str); // format to DDMMYYYY (e.g., 7092025 for 7 September, 2025)
    // your can did custom password
    return std::string(password);
  }

  // ── Misc console cosmetics ────────────────────────────────────────────
  inline constexpr bool kPrintProgressCounters = true; // Show per-chunk progress logs

} // namespace gzqr_config

#endif // GITZIPQR_CONFIG_H