# Key Attestation Lab

A small native Android app for generating a P-256 ECDSA key in Android Keystore, reading the certificate chain returned by the platform, and sharing that chain as a PEM file.

## Features

- Generates an EC key on `secp256r1` with SHA-256 signing enabled.
- Uses a fresh 32-byte challenge by default. A verifier-provided challenge can be entered as hex (up to 128 bytes).
- Optional StrongBox backing, requiring the device to be unlocked, per-use user authentication, and device-property attestation.
- Loads the certificate chain for an existing alias.
- Shares all returned X.509 certificates in chain order in a `.pem` file. The private key is never exported.

StrongBox and device-property options depend on the Android version and hardware. A device may return only a single certificate or may not provide hardware-backed attestation. The app reports the certificates Android Keystore actually returns; it does not independently validate the attestation extension or chain trust.

Open the project in Android Studio and run the `app` configuration on an Android 7.0+ device.
