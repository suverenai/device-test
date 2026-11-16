# Suveren device test

A throwaway test page for step 1 of Suveren's device-keys plan. It checks, on real phones, what
the planned phone app depends on: keys that cannot be exported, decryption, signatures,
passkeys inside the home-screen app, the camera, notifications and printing.

- Open `https://suverenai.github.io/device-test/` on the phone, add it to the home screen, open
  it from the icon, and follow the page.
- `qr.html` shows the QR code to scan; `desktop.html` is the Mac side of check 10.
- `fixtures.json` holds test keys and test data only. They protect nothing.
- Results stay on the phone until you copy them.

This repository will be archived or deleted after the test.
