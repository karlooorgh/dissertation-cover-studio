# Cover studio

Password-protected cover editor hosted with GitHub Pages.

This repository contains the unlock page and encrypted documents only. The password, original source files, and readable editor are not committed. AES-256-GCM authenticates the compressed documents; PBKDF2-SHA-256 derives the key with 600,000 iterations and a random salt. Each encrypted document has its own random nonce.

Unlocking happens locally in the browser. GitHub Pages does not perform server-side authentication. Anyone who obtains the password can decrypt these files. The repository and encrypted downloads are publicly accessible.
