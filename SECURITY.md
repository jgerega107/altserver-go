# Security

This experimental server is intended for a trusted LAN. The admin interface defaults to HTTP at the user's requested deployment model; it transmits credentials without transport encryption. Use an HTTPS reverse proxy and secure cookies if your threat model requires encrypted browser access. Do not expose the AltStore protocol or anisette endpoint publicly.

The AltStore Classic protocol does not provide strong client authentication. A device UDID allowlist is a target restriction, not proof of the caller's identity. Access to the host usbmuxd socket grants access to paired devices. Limit network access and host group membership accordingly.

Apple credentials and 2FA codes are held in memory only for the installation session. Go memory management does not guarantee immediate erasure of all string copies. Signing private keys and certificate material persist in the private state volume. Protect backups and host access. Uploaded IPA contents and helper processes are treated as untrusted input, with size/path validation, timeouts, concurrency limits, and a non-root runtime; these do not constitute a sandbox against every native signing-tool vulnerability.

Report vulnerabilities privately through the hosting repository's security advisory mechanism when enabled. Do not include real credentials, device pairing records, anisette identities, or signing keys in public issues.
