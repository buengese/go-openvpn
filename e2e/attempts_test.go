// SPDX-License-Identifier: LGPL-2.1-or-later

//go:build docker || mockserver || soak

// Reporting a reconnect's attempts, for whichever pass is driving one.

package e2e

import (
	"fmt"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
)

// summariseAttempts renders a reconnect's attempts for a failure message: what
// each one was classified as, where it stopped, and how far it got.
func summariseAttempts(attempts []vpn.Attempt) string {
	if len(attempts) == 0 {
		return "(none)"
	}
	out := ""
	for _, a := range attempts {
		if out != "" {
			out += ", "
		}
		outcome := a.Report.Outcome
		verdict := fmt.Sprintf("%s at %s", outcome.Class, outcome.Stage)
		if outcome.Succeeded {
			verdict = "succeeded"
		}
		out += fmt.Sprintf("#%d %s (%d stages)", a.N, verdict, len(a.Report.Stages))
	}
	return out
}
