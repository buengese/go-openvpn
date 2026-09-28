package profile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/buengese/go-openvpn/diag"
)

// ErrNoProfileDir reports a ca, cert or key file reference in a profile parsed
// without a directory to resolve it against. The config is fine: ParseFile and
// ParseString got its bytes with no way to find the file beside it, where
// ParsePath knows the directory and ParseFileIn takes it from the caller. A
// profile with an empty CA instead reaches TLS with nothing to verify against.
var ErrNoProfileDir = errors.New(
	"a file reference needs the profile's directory: parse with ParsePath, or with ParseFileIn when the bytes are already read")

// ErrFileRefEscapes reports a ca, cert or key reference that resolves outside
// the profile's own directory. A profile is untrusted input and this opens
// files it names, so confinement is the whole guard; it is a named error so a
// caller can tell "pointed somewhere it may not" from "the file is missing".
var ErrFileRefEscapes = errors.New("resolves outside the profile's own directory")

// maxFileRefBytes bounds a file a profile names. The name is chosen by the
// config rather than by the caller: without a limit, "ca <something enormous>"
// is read into memory in full before anything can object.
const maxFileRefBytes = 1 << 20

// pendingFileRef is a ca, cert or key file reference held between the scan
// loop and resolveFileRefs. It carries the name; the exported FileRef, which
// outlives parsing, deliberately does not.
type pendingFileRef struct {
	tag  string
	name string
	line int
}

// resolveFileRefs reads the ca, cert and key files a profile named, and
// records what became of each reference. Three rules, in order:
//
//   - An inline <tag> block wins, as it does in OpenVPN: the file is not
//     opened and the reference is recorded superseded rather than refused,
//     since naming a CA twice is redundant and not wrong.
//   - With no directory to resolve against, the reference is ErrNoProfileDir.
//   - Otherwise the file is read, confined to the profile's own directory.
//
// Every failure is diag.ClassConfig at diag.StageParse. The failure quotes the
// name the profile gave; the path it resolved to is never recorded.
func (p *Profile) resolveFileRefs(refs []pendingFileRef, baseDir string) error {
	for _, ref := range refs {
		rec := FileRef{Tag: ref.tag, Line: ref.line}
		if p.hasInlineBlock(ref.tag) {
			rec.Superseded = true
			p.FileRefs = append(p.FileRefs, rec)
			continue
		}
		if baseDir == "" {
			return configError(ErrNoProfileDir, ref.tag+" file reference")
		}
		data, err := readConfined(baseDir, ref.name)
		if err != nil {
			return configError(err, ref.tag+" file reference")
		}
		switch ref.tag {
		case "ca":
			p.CA = data
		case "cert":
			p.Cert = data
		case "key":
			p.Key = data
		}
		rec.Loaded = true
		p.FileRefs = append(p.FileRefs, rec)
	}
	return nil
}

// configError wraps a file-reference failure in the diag taxonomy: ClassConfig
// means "fix the input" and StageParse "knowable before anything was dialed",
// and both hold however reading a named file fails.
func configError(cause error, detail string) error {
	return diag.Wrap(diag.ClassConfig, diag.StageParse, cause, detail)
}

// hasInlineBlock reports whether the profile carried an inline block with the
// given tag, whatever its body holds. It asks the recorded blocks, not the
// matching field, so an empty <ca></ca> still counts as "the CA is inline".
func (p *Profile) hasInlineBlock(tag string) bool {
	for _, b := range p.InlineBlocks {
		if strings.EqualFold(b.Tag, tag) {
			return true
		}
	}
	return false
}

// readConfined reads name relative to dir, refusing anything that resolves
// outside it. The name comes from a file this process did not write, so four
// things are refused:
//
//   - an absolute name, which puts the material somewhere else entirely;
//   - a ".." walk, which filepath.Join collapses before the test sees it;
//   - a symlink out of the directory, which is why containment is tested twice;
//   - anything that is not a regular file: a fifo would block the parser.
//
// The lexical test runs first, so "../../etc/shadow" is refused whether or not
// it exists, and the size limit is enforced on the read and not only from the
// stat, since the two are separate moments.
func readConfined(dir, name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("names no file")
	}
	if filepath.IsAbs(name) {
		return nil, fmt.Errorf("%q is an absolute path and %w", name, ErrFileRefEscapes)
	}
	base, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("the profile's own directory is unusable: %w", bareErr(err))
	}
	// Join cleans, so a "keys/../../secret" walk collapses to where it
	// actually points before the test sees it.
	named := filepath.Join(base, name)
	if !within(base, named) {
		return nil, fmt.Errorf("%q %w", name, ErrFileRefEscapes)
	}

	// Both sides go through EvalSymlinks so that a profile reached through a
	// symlinked directory — a temporary directory on macOS is one — is
	// compared against the same real path its files resolve to.
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, fmt.Errorf("the profile's own directory is unusable: %w", bareErr(err))
	}
	target, err := filepath.EvalSymlinks(named)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, bareErr(err))
	}
	if !within(realBase, target) {
		return nil, fmt.Errorf("%q %w", name, ErrFileRefEscapes)
	}

	// EvalSymlinks has already resolved the last component, so this describes
	// the file that will actually be opened.
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, bareErr(err))
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", name)
	}

	f, err := os.Open(target)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, bareErr(err))
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxFileRefBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, bareErr(err))
	}
	if len(data) > maxFileRefBytes {
		return nil, fmt.Errorf("%q is larger than the %d-byte limit on a file a profile names",
			name, maxFileRefBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%q is empty", name)
	}
	return data, nil
}

// within reports whether target, an absolute cleaned path, is inside base.
// Equality is not containment: base is a directory and the material has to be
// a file in it.
func within(base, target string) bool {
	if target == base {
		return false
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// bareErr strips the path out of a filesystem error, keeping the reason.
// "No such file or directory" is what a caller needs; the absolute path it came
// with names a file on the caller's disk, and these errors are logged;
// fs.PathError separates them.
func bareErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Err != nil {
		return pe.Err
	}
	return err
}
