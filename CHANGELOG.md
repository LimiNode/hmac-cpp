# Changelog

## [Unreleased]

## [0.6.0] - Unreleased
### Security
- `secure_buffer` now coordinates page locks process-wide at page granularity,
  preventing one buffer from unlocking a page still used by another buffer.
- Replacement, copy, assignment, and string-consumption paths wipe old storage
  before release and lock replacement storage before copying secrets.

### Changed
- **Breaking ABI change:** `secure_buffer` layout and move-operation exception
  specification changed. Shared-library consumers must be fully rebuilt; do not
  use a 0.6.0 DLL/SO as a drop-in replacement for a 0.5.x build.
- CI now runs the secure-buffer regression target with page locking both enabled
  and disabled.
- CMake package compatibility is `ExactVersion` while the project remains
  pre-1.0; a 0.x minor release may contain breaking changes.

### Page-locking limitations
- The page-lock registry coordinates calls only within one loaded copy of
  hmac-cpp. Separate statically linked modules have independent registries.
- Continuing after POSIX `fork()` without `exec()` is unsupported for page
  locking because child processes do not inherit memory locks.

### Upgrade
- Rebuild every consumer against the 0.6.0 headers and library together.
- The bundled vcpkg port remains at the latest tagged release until `v0.6.0`
  is published.

## [0.5.0] - 2025-09-07
### Added
- Lifecycle management APIs and hardened zeroing for `secure_buffer`.
- Improved `secret_string` implementation for better safety and performance.
- Expanded tests covering nonce rotation and integrity checks in `secret_string`.

### Changed
- Renamed `secret.hpp` to `secret_string.hpp`; includes must update.

### Notes
- Breaking changes: header rename.

## [0.4.0] - 2025-09-06
### Added
- Base32 (RFC 4648), Base64, and Base36 encoding/decoding utilities.
- `secure_buffer<T>` zeroizing container and helpers (page locking, secret_string).
- Expanded HOTP/TOTP test coverage.

### Changed
- CMake install exports new headers.
- README updated.

### Notes
- Breaking changes: none (public API only extended).

## [0.3.0] - 2025-09-05
### Added
- PBKDF2 implementation.

### Fixed
- Documentation corrections.

