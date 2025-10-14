# SGP 2025 Bookmarklet — Technical Documentation

This document provides an in-depth description of the `sgp2025.js` bookmarklet that implements a compact, self-contained version of the SuperGenPass password generation algorithm and a minimal UI for in-page interaction.

## Overview
- File: `bookmarklet/sgp2025.js` (compact, one-line, production bookmarklet)
- File: `bookmarklet/sgp2025.extended.js` (readable, commented implementation mapping short names to descriptive ones)
- The bookmarklet opens an overlay UI that:
  - Accepts Master Password, Domain, optional Secret, and desired Length
  - Generates a deterministic password consistent with SuperGenPass rules
  - Displays the result in a masked password input by default
  - Offers Show/Hide toggle and Copy to Clipboard

## Algorithm (compatibility with SuperGenPass)
The bookmarklet reproduces the SuperGenPass workflow:
1. Hostname normalization: `extractHostname(url, removeSubdomains=true)` extracts the registrable domain (e.g., `sub.example.com` → `example.com`).
2. Input string: `masterPassword + secret + ':' + normalizedDomain`.
3. Hashing: MD5 of the input (UTF-8) → hex → bytes → standard Base64 → custom Base64 mapping:
   - `+` → `9`, `/` → `8`, `=` → `A`
4. Iterations: Perform `hr` iterations (default 10) to derive the final candidate string.
5. Policy: Ensure the chosen length substring begins with a lowercase letter and includes at least one uppercase and one digit. If not, hash again until the policy is satisfied (with a safety cap of 1000 attempts).

The compact version uses abbreviated identifiers to reduce size. The extended version uses clear names and comments that map short → descriptive.

## Implementation Details
### MD5
- Implemented inline, no external dependencies.
- Helpers (compact → descriptive):
  - `rl` → rotateLeft
  - `au` → addUnsigned
  - `FF`, `GG`, `HH`, `II` → round functions
  - `c` → convertStringToWordArray (MD5 padding)
  - `w` → wordToHex
- Important correctness notes:
  - UTF-8 normalization via `unescape(encodeURIComponent(s))` prior to hashing.
  - Padding array initialized explicitly to avoid sparse arrays in some engines.

### Base64 + Custom mapping
- `hx` converts hex to bytes
- `b64` implements Base64 encoding locally
- `cb` applies SuperGenPass custom symbol mapping (+→9, /→8, =→A)
- `hm` composes MD5→hex→bytes→base64→custom

### Hostname
- `e(u, true)` extracts and normalizes domain using a regex that tolerates various URL forms.
- `rs` removes subdomains (`a.b.example.com` → `example.com`), aligning with SGP behavior.

### Password policy and generation
- `v` validates: starts with lowercase, contains uppercase and digit.
- `gp` orchestrates normalization, iterations, policy enforcement, and returns substring of desired length.

## UI/UX
- Full-screen overlay modal with minimal inline styles for portability.
- Inputs: Master Password, Domain (pre-filled from `window.location.hostname`), optional Secret, Length.
- Actions: Generate, Close.
- Result area:
  - Password field masked by default (`type="password"`).
  - Buttons on a new row: Copy to Clipboard (silent), Show/Hide.
  - Enter key in any input triggers Generate.

## Security Considerations
- All logic runs client-side. Nothing is sent to servers.
- Clipboard operations are explicit user actions (a button click).
- The UI element is removed when closed or when the dimmed backdrop is clicked.
- No persistent storage is used by default.

## Testing and Browser Support
- Verified in Firefox and Chromium-based browsers.
- Node.js-based tests were also used to validate the core logic in isolation during development; UI is browser-only.

## File Map
- `bookmarklet/sgp2025.js`: Production, minified-style, single-line.
- `bookmarklet/sgp2025.extended.js`: Readable version (same behavior), with comments mapping short→long identifiers and code organization.
- `bookmarklet/docs/README.md`: Short guide.

## Credits
- Based on SuperGenPass: https://github.com/supergenpass/supergenpass
- This implementation aims for compatibility with the reference algorithm and policy.
