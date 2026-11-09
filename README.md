# Jeric's Trips (view-only)

Password-locked, read-only copy of Jeric's trip plans, published with GitHub Pages.

- `index.html` – the published page. Trip data is AES-256-GCM encrypted; the password unlocks it in the browser.
- `build.py` – rebuilds `index.html` from trip JSON exports: `python3 build.py <trips_dir> <password>`.
- `app-template.html` / `lock-template.html` – the app and the password screen.

Booking references, home location and costs are removed before encryption.
