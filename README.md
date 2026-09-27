# AltServer Linux

An independent Go implementation of the AltStore Classic server, with a web setup interface and a Linux container. Go is a good fit here: a small compiled server, explicit concurrency and cancellation, and direct access to the maintained go-ios device library. Mach-O signing uses the pinned zsign helper; anisette is provided by a separate self-hosted service.

**Experimental: real Apple account authentication, provisioning, installation, and iPhone Wi-Fi refresh have not yet been verified end to end.** The implementation contains the actual protocol and signing flows, not mock production backends. Apple private APIs can change independently of this project. See [device acceptance](docs/acceptance.md) before relying on it.

## Included

- Web login, device enrollment, AltStore IPA upload, Apple ID authentication, trusted-device 2FA, team selection, and installation progress.
- GrandSlam SRP authentication, device/app/group registration, development certificates and provisioning profiles.
- AltStore Classic framed TCP protocol, Bonjour discovery, anisette responses, installation, profile management, and app removal.
- Linux AMD64 and ARM64 container builds, non-root runtime, read-only filesystem, bounded uploads, and per-device serialization.
- GitHub Actions tests, image scans, and multi-platform GHCR publishing; weekly Dependabot updates.

JIT, SMS verification, arbitrary IPA bootstrap signing, AltStore PAL, and Tailscale discovery/routing changes are outside this version. No AltStore client changes are included. A developer membership does not replace host pairing or device connectivity.

## Run on Linux

Requirements: Docker Engine with Compose v2, a trusted LAN, and a paired iPhone reachable through a host usbmuxd-compatible socket. Clone with submodules, or run:

```sh
git submodule update --init --recursive
mkdir -p secrets
openssl rand -hex 24 > secrets/admin_password
chmod 700 secrets
chmod 644 secrets/admin_password
```

The parent directory restricts host access; the file must be readable by container UID 10001 because local Compose secrets are bind mounts. Save this password in your password manager. Do not commit it.

1. Install and start your distribution's `usbmuxd` and `libimobiledevice` tools on the host. Connect the iPhone by USB, unlock it, and accept **Trust This Computer**. Use `idevicepair pair` and `idevice_id -l` to confirm pairing.
2. For wireless devices, configure a host service such as [netmuxd](https://github.com/jkcoxson/netmuxd) using its documented pairing and upstream-usbmuxd configuration. Confirm the device appears through that socket with USB disconnected. Pairing records stay on the host; the application container only mounts the socket. Docker alone does not establish Wi-Fi pairing.
3. Create `.env` with your socket and LAN interface, for example:

```dotenv
USBMUXD_SOCKET_PATH=/var/run/usbmuxd
USBMUXD_GID=0
ALTSERVER_INTERFACE=eth0
```

Use the actual numeric socket group (`stat -c %g /var/run/usbmuxd`) and interface (`ip link`). For netmuxd, set its socket path instead. The group must have socket connect permission. Do not make pairing files or sockets world-writable. Socket recreation by the host service may require recreating the app container's bind mount.

```sh
docker compose up --build -d
docker compose logs -f altserver anisette
```

Open `http://YOUR_LINUX_HOST:8080`, sign in with the generated admin password, and check connection status. Obtain an original AltStore Classic IPA from the [official AltStore releases](https://github.com/altstoreio/AltStore/releases), select your paired device, and submit the IPA with your Apple ID credentials. Complete the trusted-device verification and team selection when requested. Successful bootstrap installation automatically enables refresh for that device. Existing installations can be enrolled using **Enable refresh**.

Follow iOS prompts to trust the developer and enable Developer Mode when required. Keep the server running and the phone on the same LAN for discovery and refresh. Background refresh scheduling belongs to iOS and AltStore; the server cannot guarantee when it runs.

The anisette companion may download its runtime components and provision its identity on first startup; allow it to finish before installation. Its identity persists in a separate volume. It is digest-pinned and published only on host loopback port 6969.

### Container permissions and networking

The application runs as UID/GID **10001**, drops all capabilities, prohibits privilege escalation, and uses a read-only root filesystem. State and work directories are named volumes; `/tmp` is a bounded tmpfs. The slim multi-stage runtime contains only the Go binary, zsign, required libraries, certificates, and license notices. No Docker socket, USB bus, or privileged mode is needed.

Compose uses **Linux host networking** so Bonjour multicast and the advertised TCP address work on the LAN. Permit TCP 8080 (admin), TCP 6968 (AltStore), and UDP 5353 (mDNS) only on your trusted LAN. Admin HTTP is intentionally unencrypted: Apple credentials and uploaded data cross that connection. Do not expose either server port to the public Internet. The AltStore protocol has no independent client authentication; enrolled UDIDs limit targets but are not a security boundary against a hostile LAN client.

This is a non-root application container, not a promise of compatibility with a rootless Docker daemon. Rootless daemon UID mapping, host sockets, and multicast require additional host configuration. WSL is useful for builds and tests; production-like Wi-Fi discovery additionally needs working LAN multicast and device forwarding. USB pairing in WSL requires configuring Windows-to-WSL USB forwarding separately.

## Configuration

| Variable | Default / purpose |
| --- | --- |
| `ALTSERVER_ADMIN_PASSWORD_FILE` | Required on first start; 16–72 byte admin password file. Supplying a new value rotates the stored bcrypt hash on restart. |
| `ALTSERVER_WEB_ADDR` | `:8080`; web listener |
| `ALTSERVER_LISTEN_ADDR` | `:6968`; AltStore TCP listener |
| `ALTSERVER_INTERFACE` | Empty = all eligible interfaces; select your LAN interface for discovery |
| `ALTSERVER_DISCOVERY` | `true`; Bonjour advertisement |
| `ALTSERVER_ANISETTE_URL` | `http://127.0.0.1:6969`; anisette v1 HTTP endpoint |
| `ALTSERVER_STATE_DIR` | `/var/lib/altserver`; identity, enrollment, certificates and private keys |
| `ALTSERVER_WORK_DIR` | `/tmp/altserver` outside Docker; `/var/cache/altserver` in the image |
| `ALTSERVER_ZSIGN` | `zsign`; signing executable |
| `ALTSERVER_MAX_IPA_BYTES` | `1073741824`; 1 GiB upload limit; expanded archives also limited to 4 GiB |
| `ALTSERVER_OPERATION_TIMEOUT` | `15m`; setup/refresh deadline |
| `ALTSERVER_SECURE_COOKIE` | `false`; set true only behind HTTPS |
| `USBMUXD_SOCKET_ADDRESS` | go-ios socket address; Compose supplies `unix:///run/host-usbmuxd/usbmuxd` |

Compose exposes its image, listener, interface, and socket settings through `.env`. Add other overrides to the service environment explicitly. Back up the state and anisette volumes securely; losing server identity can break existing client discovery, and losing signing keys may require creating another certificate. Apple passwords, verification codes, and login sessions are not persisted. Signing keys are persisted with private permissions; protect the volume and backups. Expired temporary uploads are cleaned on restart. Never run two servers against the same state directory.

## Build and verify

Targets **Go 1.27.1**, the latest stable release verified on 2026-09-27. Go dependencies and tool versions are in `go.mod`/`go.sum`; image digests, Actions SHAs, and the zsign submodule pin make upgrades reviewable. The device library uses the latest upstream commit rather than its older release tag.

```sh
go build -trimpath -o bin/altserver ./cmd/altserver
go vet ./...
go test -race ./...
go tool govulncheck ./...
go tool actionlint
docker build -t altserver:local .
bash scripts/container-smoke.sh altserver:local
```

Build the application on Linux or WSL. Race tests require a C compiler. The Go binary needs zsign and an anisette service at runtime; the container packages these dependencies or connects the companion for you. Tests use synthetic profiles, independent SRP vectors, mock Apple HTTP services, and fake device backends. They never need your Apple account.

## GHCR and updates

Push this repository to your GitHub account with `main` as the default branch. The included workflow validates pull requests without publishing. Pushes to `main` publish `ghcr.io/OWNER/REPOSITORY:edge` and a commit tag after tests and native AMD64/ARM64 container checks pass. Semantic version tags such as `v0.1.0` publish version tags and `latest` for stable releases. Images include SBOM and provenance attestations. Package publishing uses the repository's `GITHUB_TOKEN` with `packages: write`; no registry password secret is needed. Repository/organization Actions policies must allow that permission and the selected runners. A new GHCR package may initially be private; configure its visibility as desired.

To use a published image, set `ALTSERVER_IMAGE=ghcr.io/OWNER/REPOSITORY:edge`, then run `docker compose pull && docker compose up -d --no-build`. Dependabot opens weekly updates for Go modules/tools, Actions, Dockerfiles, Compose images, and the signing submodule. Review and test updates before merging; it does not auto-merge.

Repository: [jgerega107/altserver-go](https://github.com/jgerega107/altserver-go). Publishing starts when commits are pushed to `main`; the workflow must pass before an image becomes available.

## References and license

The protocol and Apple service behavior were studied from [AltStore](https://github.com/altstoreio/AltStore), [AltSign](https://github.com/rileytestut/AltSign), and [AltServer-Linux](https://github.com/NyaMisty/AltServer-Linux). The older Linux implementation was treated as a reference, not as an up-to-date dependency. Device access uses [go-ios](https://github.com/danielpaulus/go-ios); signing uses [zsign](https://github.com/zhlynn/zsign); anisette uses [anisette-v3-server](https://github.com/Dadoum/anisette-v3-server).

AGPL-3.0-only. See [LICENSE](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.md). This project is not affiliated with Apple or the AltStore team.
