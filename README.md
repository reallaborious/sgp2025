# SGP 2025 Bookmarklet

This bookmarklet generates site-specific passwords compatible with the SuperGenPass algorithm. It is a self-contained JavaScript snippet intended for use in browser bookmarks.

- Core file: `sgp2025.js`
- Optional: `sgp2025.extended.js` (readable, documented version)
- Detailed docs: see `docs/sgp2025-bookmarklet.md`

Based on SuperGenPass. Original project:
- Repository: https://github.com/supergenpass/supergenpass
- License: see upstream repository

How to use
1. Open `sgp2025.js` and copy the single line that starts with `javascript:(function(){...`.
2. Create a new browser bookmark and paste that line into the URL/location field.
3. Visit any site, click the bookmarklet, enter your Master Password and the Domain (pre-filled), optionally a Secret, choose length, then press Generate. Copy using the Copy button.

Notes
- Password is masked by default; use "Show password" to toggle visibility.
- Copy button copies the real password silently (no alerts).
- Works in Firefox and Chromium-based browsers.
