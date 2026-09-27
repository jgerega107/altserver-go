# Real-device acceptance

These checks are **pending**. Unit tests, race tests, mock service tests, cross-compilation, and container smoke tests cannot establish compatibility with Apple's live private services or a physical iPhone.

Use a test device and your own account. Record iOS version, AltStore IPA version, image revision, host distribution, usbmuxd/netmuxd versions, account team type, and the result. Do not record passwords, verification codes, anisette headers, pairing records, private keys, or complete HTTP payloads.

1. Pair over USB. Confirm device listing, enrollment, disabling enrollment, and reconnect after host service restart.
2. Confirm self-hosted anisette becomes available and keeps its identity after restart.
3. Bootstrap an official AltStore Classic IPA with a free account: trusted-device 2FA, team selection, certificate creation, app/group registration, profile generation, signing, and installation. Confirm the installed app launches and embedded server identity is correct.
4. Repeat installation to check certificate reuse. Existing unrelated certificates must not be revoked. Test a paid developer team separately; check that unrelated profiles remain installed.
5. Open AltStore and manually refresh over USB. Then disconnect USB, verify host wireless device listing, and refresh over Wi-Fi on the same LAN. Check Bonjour discovery and progress/error responses.
6. Refresh multiple apps and test free-account activation/deactivation limits. Confirm unrelated paid profiles survive, active profile selection behaves as expected, and temporary profile removal is restored after an injected installation failure.
7. Cancel while waiting for 2FA, during signing, and during transfer. Disconnect the phone during transfer and restart the server. Check cleanup and recovery. Abrupt host power loss cannot guarantee profile restoration; verify the recovery procedure on the test device.
8. Leave the server running and observe actual AltStore/iOS background refresh. This scheduling is not controlled by the server.
9. Repeat on native AMD64 and ARM64 hosts with the hardened Compose configuration. Confirm socket permissions without root/privileged application execution.

JIT, remote Tailscale discovery, SMS-only account verification, and AltStore PAL are not acceptance targets for this version. A successful build must not be presented as a successful device test.
