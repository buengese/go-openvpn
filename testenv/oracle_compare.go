// SPDX-License-Identifier: LGPL-2.1-or-later

// The four-cell comparison of our outcome against the reference client's.

package testenv

import (
	"fmt"

	"github.com/openlawsvpn/go-openlawsvpn/diag"
)

// The four-cell comparison
// ---------------------------------------------------------------------------

// Cell is one square of the comparison table: what it means that our client
// and stock openvpn each did what they did.
type Cell int

// The four cells. Exactly one of them generates work.
const (
	// CellWorkingAsIntended is both connecting. Record the features
	// exercised; there is nothing to fix.
	CellWorkingAsIntended Cell = iota
	// CellOurGap is we fail and stock openvpn connects. This is the only
	// cell that generates work: the config and the endpoint are both fine,
	// so the difference is ours.
	CellOurGap
	// CellBadConfigOrDeadEndpoint is both failing. Exclude it from the
	// denominator; it is not a defect in this library.
	CellBadConfigOrDeadEndpoint
	// CellSurprising is we connect and stock openvpn does not. Investigate:
	// most often the reference binary is a different build from the one the
	// config was written for, which is why OracleResult records both.
	CellSurprising
)

// cellNames are the stable tokens Cell.String returns.
var cellNames = [...]string{
	CellWorkingAsIntended:       "working-as-intended",
	CellOurGap:                  "our-gap",
	CellBadConfigOrDeadEndpoint: "bad-config-or-dead-endpoint",
	CellSurprising:              "surprising",
}

// String returns the cell's stable token, or a "cell(N)" placeholder when the
// value is outside the defined range.
func (c Cell) String() string {
	if c < 0 || int(c) >= len(cellNames) {
		return fmt.Sprintf("cell(%d)", int(c))
	}
	return cellNames[c]
}

// cellActions are what to do about each cell: record it, work it, exclude it,
// or go and look.
var cellActions = [...]string{
	CellWorkingAsIntended:       "record features exercised",
	CellOurGap:                  "the only cell that generates work",
	CellBadConfigOrDeadEndpoint: "exclude; not a defect",
	CellSurprising:              "investigate — often a stale local openvpn",
}

// Action returns what to do about the cell.
func (c Cell) Action() string {
	if c < 0 || int(c) >= len(cellActions) {
		return ""
	}
	return cellActions[c]
}

// GeneratesWork reports whether the cell is the one that produces a task, which
// is CellOurGap and only CellOurGap.
func (c Cell) GeneratesWork() bool { return c == CellOurGap }

// ClientOutcome is our own client's side of the comparison, reduced to the
// three things the four-cell table needs.
//
// It is a plain struct rather than a *diag.SessionReport so that testenv does
// not have to import the root package, which it cannot: the root package's own
// integration tests import testenv. Build one with ClientOutcomeFromReport.
type ClientOutcome struct {
	// Connected reports whether our client reached a working tunnel.
	Connected bool
	// Class is the diag class our attempt ended with, meaningless when
	// Connected is true.
	Class diag.Class
	// Stage is the furthest stage our attempt reached.
	Stage diag.Stage
}

// ClientOutcomeFromReport reduces a diag.SessionReport to the comparison
// inputs. A nil report yields the zero outcome, which reads as "did not
// connect": a run that produced no report certainly produced no tunnel.
func ClientOutcomeFromReport(r *diag.SessionReport) ClientOutcome {
	if r == nil {
		return ClientOutcome{}
	}
	return ClientOutcome{
		Connected: r.Outcome.Succeeded,
		Class:     r.Outcome.Class,
		Stage:     r.Outcome.Stage,
	}
}

// Agreement says whether our client and stock openvpn reached the same verdict
// about a config, for the case the cell cannot speak to: both of them failed,
// and the question is whether they failed at the same thing.
//
// It is keyed on the diag class and never on the stage. The stage is a
// systematic difference between the two clients rather than a tie-breaker: our
// client reports AUTH_FAILED as ClassAuth at StagePush, correctly, since
// OpenVPN sends it in place of PUSH_REPLY after a key-method-2 exchange the
// server accepted, where ClassifyReferenceLog maps the same rejection to
// StageAuth, equally correctly for a reader of stock openvpn's log. Comparing
// on the stage would report a disagreement on every credential rejection and on
// nothing real. Verdict.String reports both stages all the same, as two
// positions on one agreed failure.
type Agreement int

// How far the two clients agree.
const (
	// AgreementSplit is one of them connecting and the other not. The cell
	// already says everything there is to say; there is no pair of failures
	// to compare, and both CellOurGap and CellSurprising are this.
	AgreementSplit Agreement = iota
	// AgreementBothConnected is both connecting.
	AgreementBothConnected
	// AgreementSameClass is both failing in the same class. The stages may
	// differ, and for a credential rejection they always do.
	AgreementSameClass
	// AgreementDifferentClass is both failing, in different classes. It is the
	// only value that is a real disagreement: the two clients agree the config
	// does not work and give different reasons, so at most one can be right.
	AgreementDifferentClass
)

// agreementNames are the stable tokens Agreement.String returns.
var agreementNames = [...]string{
	AgreementSplit:          "split",
	AgreementBothConnected:  "both-connected",
	AgreementSameClass:      "same-class",
	AgreementDifferentClass: "different-class",
}

// String returns the agreement's stable token, or an "agreement(N)" placeholder
// when the value is outside the defined range.
func (a Agreement) String() string {
	if a < 0 || int(a) >= len(agreementNames) {
		return fmt.Sprintf("agreement(%d)", int(a))
	}
	return agreementNames[a]
}

// Agrees reports whether the two clients reached the same verdict: both
// connected, or both failed in the same class. A split is not a disagreement
// about the reason — it is the cell doing its job — so it is false here.
func (a Agreement) Agrees() bool {
	return a == AgreementBothConnected || a == AgreementSameClass
}

// Verdict is the oracle's result for one config: what we did, what stock
// openvpn did, which cell that puts the config in, and how far the two agree.
//
// Rolled up per provider it is also the rot detector: a provider where nothing
// connects and stock openvpn fails across the board has a stale account or
// config set and needs a human, not a bug fix.
type Verdict struct {
	// Cell is which square of the four-cell table this config landed in.
	Cell Cell
	// Agreement is how far the two outcomes agree. It is keyed on the class
	// alone; see the type's documentation for why the stage is excluded.
	Agreement Agreement
	// Ours is our client's outcome.
	Ours ClientOutcome
	// Reference is the stock openvpn run it was compared against.
	Reference OracleResult
}

// Compare produces the oracle's verdict from the two outcomes.
func Compare(ours ClientOutcome, ref OracleResult) Verdict {
	var cell Cell
	switch {
	case ours.Connected && ref.Connected:
		cell = CellWorkingAsIntended
	case !ours.Connected && ref.Connected:
		cell = CellOurGap
	case !ours.Connected && !ref.Connected:
		cell = CellBadConfigOrDeadEndpoint
	default:
		cell = CellSurprising
	}

	agreement := AgreementSplit
	switch {
	case ours.Connected && ref.Connected:
		agreement = AgreementBothConnected
	case !ours.Connected && !ref.Connected && ours.Class == ref.Class:
		agreement = AgreementSameClass
	case !ours.Connected && !ref.Connected:
		agreement = AgreementDifferentClass
	}
	return Verdict{Cell: cell, Agreement: agreement, Ours: ours, Reference: ref}
}

// String renders the verdict as one line: the cell, what the two clients did,
// and the openvpn release that arbitrated.
//
// Both stages are always in the line. Where the classes agree they are written
// as two positions on one failure — "both fail auth — ours at push, stock
// openvpn at auth" — rather than side by side, which would read as a dispute.
func (v Verdict) String() string {
	var body string
	switch v.Agreement {
	case AgreementBothConnected:
		body = "both connect"
	case AgreementSameClass:
		body = fmt.Sprintf("both fail %s — ours at %s, stock openvpn at %s",
			v.Ours.Class, v.Ours.Stage, v.Reference.Stage)
	case AgreementDifferentClass:
		body = fmt.Sprintf("classes differ — ours fails %s@%s, stock openvpn fails %s@%s",
			v.Ours.Class, v.Ours.Stage, v.Reference.Class, v.Reference.Stage)
	default:
		ours, theirs := "connects", "connects"
		if !v.Ours.Connected {
			ours = fmt.Sprintf("fails %s@%s", v.Ours.Class, v.Ours.Stage)
		}
		if !v.Reference.Connected {
			theirs = fmt.Sprintf("fails %s@%s", v.Reference.Class, v.Reference.Stage)
		}
		body = fmt.Sprintf("ours %s, stock openvpn %s", ours, theirs)
	}
	return fmt.Sprintf("%s: %s [stock openvpn %s] — %s",
		v.Cell, body, v.Reference.Release, v.Cell.Action())
}
