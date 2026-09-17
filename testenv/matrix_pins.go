package testenv

// ---------------------------------------------------------------------------
// Pinned image inputs
//
// These mirror docker/openvpn-server/versions.env, which is the file build.sh
// sources. TestPinsMatchVersionsEnv (a plain unit test, no Docker required)
// fails if the two ever drift.
// ---------------------------------------------------------------------------

// MatrixImageRepo is the local-only image repository the matrix server images
// are tagged into. Images are built by `make matrix-images` and never pushed.
const MatrixImageRepo = "openlawsvpn-test/openvpn-server"

// Pinned OpenVPN releases built into the matrix images. Never a floating tag:
// a moving version makes every captured result irreproducible.
const (
	// OpenVPN24Version is the exact 2.4 release the matrix builds. 2.4
	// predates TLS keying-material-exporter support, so it forces the
	// classic OpenVPN PRF path.
	OpenVPN24Version = "2.4.12"
	// OpenVPN25Version is the exact 2.5 release the matrix builds.
	OpenVPN25Version = "2.5.11"
	// OpenVPN26Version is the exact 2.6 release the matrix builds.
	OpenVPN26Version = "2.6.22"
)

// SHA-256 of each pinned upstream release tarball, verified during the image
// build. The values were cross-checked against the detached OpenPGP signatures
// published next to the tarballs.
const (
	// OpenVPN24SHA256 is the SHA-256 of openvpn-2.4.12.tar.gz.
	OpenVPN24SHA256 = "66952d9c95490e5875f04c9f8fa313b5e816d1b7b4d6cda3fb2ff749ad405dee"
	// OpenVPN25SHA256 is the SHA-256 of openvpn-2.5.11.tar.gz.
	OpenVPN25SHA256 = "7e2672119bd4639819d560f332a8b9b7e28f562425c77899f36d419fe4265f56"
	// OpenVPN26SHA256 is the SHA-256 of openvpn-2.6.22.tar.gz.
	OpenVPN26SHA256 = "f46df740f05f86020137a41cfc8814352391cf861ed57f57b4e815cb97c1d2cf"
)

// Base images, pinned by manifest digest. 2.4 and 2.5 need OpenSSL 1.1.1
// (bullseye) — 2.4 does not build against OpenSSL 3.x. 2.6 requires OpenSSL 3.x
// (bookworm).
const (
	// OpenVPN24Base is the pinned base image for the 2.4 matrix image.
	OpenVPN24Base = "debian:bullseye-slim@sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd"
	// OpenVPN25Base is the pinned base image for the 2.5 matrix image.
	OpenVPN25Base = "debian:bullseye-slim@sha256:e5b6442dd2e9684cf5e87d8338b5968f3b348636fc0be6d7850a381e3731a2bd"
	// OpenVPN26Base is the pinned base image for the 2.6 matrix image.
	OpenVPN26Base = "debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
)
