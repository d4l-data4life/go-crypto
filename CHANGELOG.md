# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [v1.1.0] - 2026-07-30

### Added

- v4 hybrid encryption (slot-based): `EncryptHybridV4` wraps the payload data key into one slot
  per recipient — `ECSlot` (ECIES over secp256k1), `RSASlot` (RSA-OAEP) or `AESSlot`
  to v1–v3, opening a slot only with a key whose `(decrypterID, keyAlg)` match and trying every
  match — so a slot addressed to another recipient is refused and rotated keys keep decrypting.
  Version 4.

### Changed

- Move to d4l-data4life

### Fixed

- `Decrypter.Decrypt` no longer trusts on-wire length fields: corrupt or malicious records
  now fail with a clean error instead of triggering huge allocations or panics (v1 plaintext
  length overflowing the block-size round-up into a slicing panic; v3 recovery branch with a
  non-block-multiple key blob panicking in CBC `CryptBlocks`).

## [v1.0.0] - 

### Changed

- Move to d4l-data4life

[Unreleased]: https://github.com/d4l-data4life/go-crypto/compare/v1.1.0...HEAD
[v1.1.0]: https://github.com/d4l-data4life/go-crypto/compare/v1.0.0...v1.1.0
[v1.0.0]: https://github.com/d4l-data4life/go-crypto/releases/tag/v1.0.0
