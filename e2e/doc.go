// SPDX-License-Identifier: LGPL-2.1-or-later

// Package e2e holds the end-to-end tests of the OpenVPN client: the ones that
// stand up a real peer and drive a whole connection through it.
//
// It has no non-test code, and every test in it is selected by a build tag so
// that no pass can acquire a dependency by accident:
//
//	docker      real pinned OpenVPN servers in containers (make test-e2e)
//	mockserver  testenv/mockserver as a subprocess, no Docker (make test-mock)
//	soak        one tunnel held open for hours (make test-soak SOAK=1h)
//
// See docs/testing.md for what each pass costs and how it fails when a
// prerequisite is missing.
package e2e
