// SPDX-License-Identifier: LGPL-2.1-or-later

// Stock openvpn as a client: the rig's own self-check that an entry is well
// formed before our client is asked to complete it.

package testenv

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

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
