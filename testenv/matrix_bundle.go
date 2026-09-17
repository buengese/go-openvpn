// SPDX-License-Identifier: LGPL-2.1-or-later

// The config bundle a matrix container is handed at startup.

package testenv

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"time"
)

// Config bundle
// ---------------------------------------------------------------------------

// bundleFile is one file in the base64 tar handed to a container.
type bundleFile struct {
	name string
	body string
	mode int64
}

// matrixBundle packs the server config and PKI into a base64-encoded tar, which
// the entrypoint unpacks into /etc/openvpn. Passing it through the environment
// avoids bind mounts entirely, so no key material is ever written to a path
// shared with the host.
func matrixBundle(e MatrixEntry, pki MatrixPKI) (string, error) {
	files := []bundleFile{
		{"server.conf", e.ServerConfig(), 0o644},
		{"ca.crt", pki.CACertPEM, 0o644},
		{"server.crt", pki.ServerCertPEM, 0o644},
		{"server.key", pki.ServerKeyPEM, 0o600},
	}
	if pki.StaticKey != "" {
		files = append(files, bundleFile{"ta.key", pki.StaticKey, 0o600})
	}
	if e.Auth.RequiresCredentials() {
		// 0o755, not 0o644: OpenVPN execve()s the hook directly, and a hook
		// it cannot execute fails the connection at the same point a wrong
		// password does. The entrypoint re-asserts the mode for the same
		// reason.
		files = append(files, bundleFile{authVerifyFileName, authVerifyScript(), 0o755})
	}
	return tarBundle(files)
}

// tarBundle renders files as a base64-encoded tar archive.
func tarBundle(files []bundleFile) (string, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		hdr := &tar.Header{
			Name:    f.name,
			Mode:    f.mode,
			Size:    int64(len(f.body)),
			ModTime: time.Unix(0, 0),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", err
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// ---------------------------------------------------------------------------
