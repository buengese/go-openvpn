// SPDX-License-Identifier: LGPL-2.1-or-later

// Stock openvpn as a client: the rig's own self-check that an entry is well
// formed before our client is asked to complete it.

package testenv

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Reference-client self-check
// ---------------------------------------------------------------------------

// ReferenceClientResult is the outcome of running a stock OpenVPN client of the
// same pinned version against a matrix server.
type ReferenceClientResult struct {
	// Connected reports whether the reference client completed its
	// initialization sequence, i.e. handshake, auth and push all succeeded.
	Connected bool
	// Log is the reference client's container log.
	Log string
	// Classification is the same verdict the reference oracle would reach
	// from this log, so an entry that is meant to be refused can be checked
	// against the reason it was refused rather than merely against the fact.
	// "Did not connect" is also what a server that failed to start produces.
	Classification Classification
}

// ContainerIP returns the server container's address on Docker's default
// bridge network. It is how a second container reaches the server without
// going through a published host port.
func (s *MatrixServer) ContainerIP() (string, error) {
	// Docker 29 dropped the flattened NetworkSettings.IPAddress field, so
	// walk the per-network map and take the first address offered.
	out, err := exec.Command("docker", "inspect",
		"-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", s.ContainerID).Output()
	if err != nil {
		return "", fmt.Errorf("testenv: docker inspect container IP: %w", err)
	}
	for _, ip := range strings.Fields(string(out)) {
		if ip != "" {
			return ip, nil
		}
	}
	return "", errors.New("testenv: container has no IPv4 address on its Docker network")
}

// ContainerIP6 returns the server container's global IPv6 address. It is only
// populated for entries that were given a throwaway IPv6 network, i.e. those
// whose Family is not AFInet.
func (s *MatrixServer) ContainerIP6() (string, error) {
	out, err := exec.Command("docker", "inspect",
		"-f", "{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}} {{end}}", s.ContainerID).Output()
	if err != nil {
		return "", fmt.Errorf("testenv: docker inspect container IPv6: %w", err)
	}
	for _, ip := range strings.Fields(string(out)) {
		if ip != "" {
			return ip, nil
		}
	}
	return "", errors.New("testenv: container has no global IPv6 address")
}

// ContainerProfile returns the .ovpn profile a sibling container should use to
// reach this server: the one generated from this server's matrix entry, but
// pointed at the container's own address on the Docker network rather than at
// the published host port, which no other container can reach. It returns an
// error wrapping ErrUnimplemented for an IPv6 entry whose throwaway IPv6
// network could not be created; callers should skip on that rather than fail.
func (s *MatrixServer) ContainerProfile() (string, error) {
	// An IPv6 entry dials the server's global IPv6 address, which only
	// exists if the throwaway IPv6 network was created.
	var (
		remote string
		err    error
	)
	if s.Entry.Family == AFInet6 {
		if s.networkErr != nil {
			return "", fmt.Errorf("%w: %s: no IPv6 Docker network: %v",
				ErrUnimplemented, s.Entry.Name, s.networkErr)
		}
		remote, err = s.ContainerIP6()
	} else {
		remote, err = s.ContainerIP()
	}
	if err != nil {
		return "", err
	}

	// A stock OpenVPN client in a container has no terminal to be prompted on,
	// so it is given the file form and the file itself; see containerSideFiles.
	// Both paths are absolute because the entrypoint runs openvpn with the
	// working directory left at /, and OpenVPN resolves a relative path in a
	// config against the working directory rather than the config's own.
	return s.Entry.ClientProfile(ClientProfileOptions{
		Remote:          remote,
		Port:            ContainerPort,
		CACertPEM:       s.PKI.CACertPEM,
		ClientCertPEM:   s.PKI.ClientCertPEM,
		ClientKeyPEM:    s.PKI.ClientKeyPEM,
		StaticKey:       s.PKI.StaticKey,
		CredentialsFile: clientCredentialsPath,
		CAFile:          clientCAPath,
		// The container has its own network namespace with no other process
		// in it and nothing listens on anything but ContainerPort, so the
		// neighbouring port is dead by construction rather than by probe.
		DeadRemotePort: ContainerPort + 1,
	}), nil
}

// containerSideFiles returns the extra bundle files a containerised stock
// OpenVPN client needs beside the profile ContainerProfile generates: the
// credentials file for an AuthUserPass entry, the CA for a CAFile entry, and
// nothing at all for an entry whose profile is self-contained.
func (s *MatrixServer) containerSideFiles() []bundleFile {
	var out []bundleFile
	if s.Entry.Auth.RequiresCredentials() {
		out = append(out, bundleFile{MatrixCredentialsFile, credentialsFileBody(), 0o600})
	}
	if s.Entry.CASource == CAFile {
		out = append(out, bundleFile{MatrixCAFile, s.PKI.CACertPEM, 0o644})
	}
	return out
}

// OracleOptions returns the options that point a RunOracle call at this
// server: the same pinned OpenVPN build the server runs, and the same Docker
// network, so the reference client can reach it.
//
// Pair it with ContainerProfile:
//
//	profile, err := srv.ContainerProfile()
//	res, err := testenv.RunOracle(ctx, profile, srv.OracleOptions())
func (s *MatrixServer) OracleOptions() OracleOptions {
	o := OracleOptions{Version: s.Entry.Version, Network: s.network}
	// Whatever ContainerProfile points at by path, an oracle run has to carry.
	// A caller can replace the credentials entry to run with a password the
	// server will reject, which is how a deliberate auth failure is built.
	for _, f := range s.containerSideFiles() {
		if o.Files == nil {
			o.Files = map[string]string{}
		}
		o.Files[f.name] = f.body
	}
	return o
}

// CheckWithReferenceClient runs a stock OpenVPN client — the same pinned
// version, from the same image — against this server in a throwaway container,
// and reports whether it connected.
//
// This is the matrix's self-check: it asserts on the rig rather than on our
// client, proving that ServerConfig and ClientProfile, generated from one
// MatrixEntry, agree on the wire. RunOracle is the oracle proper, sharing the
// container machinery below but judging an arbitrary config. An error wrapping
// ErrUnimplemented means the self-check cannot cover this entry; callers should
// skip on that rather than fail.
func (s *MatrixServer) CheckWithReferenceClient(timeout time.Duration) (ReferenceClientResult, error) {
	var res ReferenceClientResult

	profile, err := s.ContainerProfile()
	if err != nil {
		return res, err
	}

	files := append([]bundleFile{{"client.conf", profile, 0o600}}, s.containerSideFiles()...)
	run, err := runReferenceClient(context.Background(), referenceClientSpec{
		image:   s.Image,
		network: s.network,
		files:   files,
		timeout: timeout,
	})
	res.Connected, res.Log = run.connected, run.log
	res.Classification = ClassifyReferenceLog(run.log, run.timedOut)
	return res, err
}

// ---------------------------------------------------------------------------
// The shared stock-OpenVPN client container
//
// Both callers need the same thing: unpack a config into a throwaway container,
// run the pinned openvpn against it, and watch the log until it either reports
// a completed initialization sequence or stops. Only the inputs differ.
// ---------------------------------------------------------------------------

// referencePollInterval is how often the client container's log is re-read.
const referencePollInterval = 100 * time.Millisecond

// referenceClientSpec describes one stock-OpenVPN client container run.
type referenceClientSpec struct {
	// image is the pinned matrix image to run.
	image string
	// network is the Docker network to attach to, empty for the default
	// bridge.
	network string
	// files is the bundle unpacked into /etc/openvpn. It must contain
	// "client.conf"; anything else is placed alongside it.
	files []bundleFile
	// timeout bounds the watch, not the container: on expiry the container
	// is removed and whatever log it produced is returned.
	timeout time.Duration
}

// referenceClientRun is the raw outcome of a stock-OpenVPN client container.
type referenceClientRun struct {
	// log is the container's complete log.
	log string
	// connected reports that the readiness marker appeared.
	connected bool
	// banner is the openvpn version banner parsed out of the log.
	banner string
	// elapsed is how long the container was watched.
	elapsed time.Duration
	// timedOut reports that the watch expired with the container running.
	timedOut bool
}

// runReferenceClient starts a stock OpenVPN client container and watches it
// until it connects, exits, or the spec's timeout expires. An error means the
// container could not be created; a client that failed to connect is reported
// in the run, not as an error.
//
// The container has its own network namespace, so nothing it does — including
// installing the routes and resolver a server pushes it — can reach the host.
// NET_ADMIN and /dev/net/tun are scoped to that namespace too.
func runReferenceClient(ctx context.Context, spec referenceClientSpec) (referenceClientRun, error) {
	var run referenceClientRun

	bundle, err := tarBundle(spec.files)
	if err != nil {
		return run, fmt.Errorf("testenv: build client bundle: %w", err)
	}

	runArgs := []string{"run", "-d",
		"--label", MatrixLabel,
		"--cap-add=NET_ADMIN",
		"--device=/dev/net/tun",
		"-e", "OVPN_CONFIG=client.conf",
		"-e", "OVPN_BUNDLE_B64=" + bundle,
	}
	if spec.network != "" {
		runArgs = append(runArgs, "--network", spec.network)
	}
	runArgs = append(runArgs, spec.image)

	out, err := exec.CommandContext(ctx, "docker", runArgs...).CombinedOutput()
	if err != nil {
		return run, fmt.Errorf("testenv: docker run reference client: %w (output: %s)",
			err, strings.TrimSpace(string(out)))
	}
	id := strings.TrimSpace(string(out))
	defer func() {
		// Not CommandContext: the container must be removed even when the
		// caller's context is already cancelled.
		_ = exec.Command("docker", "rm", "-f", id).Run()
	}()

	start := time.Now()
	deadline := start.Add(spec.timeout)
	for {
		run.log, _ = containerLogs(id)
		if strings.Contains(run.log, matrixReadyMarker) {
			run.connected = true
			break
		}
		if !containerRunning(id) {
			// Re-read: openvpn's last lines — the fatal error, usually —
			// are commonly written between the read above and the exit.
			run.log, _ = containerLogs(id)
			break
		}
		if time.Now().After(deadline) {
			run.timedOut = true
			break
		}
		select {
		case <-ctx.Done():
			run.elapsed = time.Since(start)
			return run, ctx.Err()
		case <-time.After(referencePollInterval):
		}
	}
	run.elapsed = time.Since(start)
	run.banner = openvpnBanner(run.log)
	return run, nil
}

// containerLogs returns a container's combined stdout and stderr.
func containerLogs(id string) (string, error) {
	out, err := exec.Command("docker", "logs", id).CombinedOutput()
	return string(out), err
}

// containerRunning reports whether a container is still up.
func containerRunning(id string) bool {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", id).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// ---------------------------------------------------------------------------
