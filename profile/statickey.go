package profile

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// StaticKeySize is the length of an OpenVPN static key in bytes: sixteen lines
// of thirty-two hexadecimal digits, what OpenVPN calls a 2048-bit key. tls-auth
// and tls-crypt both derive every sub-key they use — send HMAC, receive HMAC,
// cipher key — from exactly this much material, so any other length is not a
// short key, it is not a key.
const StaticKeySize = 256

// staticKeyHeader and staticKeyFooter delimit the key inside a generated key
// file. Both are optional: OpenVPN accepts a bare run of hex digits, and so
// does ParseStaticKey.
const (
	staticKeyHeader = "-----BEGIN OpenVPN Static key V1-----"
	staticKeyFooter = "-----END OpenVPN Static key V1-----"
)

// redactedStaticKey stands in for the bytes in every rendering of a StaticKey.
const redactedStaticKey = "[OpenVPN static key: 256 bytes, redacted]"

// StaticKey is an OpenVPN 2048-bit static key: 256 bytes, conventionally
// written as a "-----BEGIN OpenVPN Static key V1-----" block of hexadecimal.
// It is the material behind a <tls-auth> or <tls-crypt> block.
//
// A StaticKey is a secret, and the type enforces that rather than the call
// sites: String, GoString and MarshalJSON all yield a fixed placeholder, so a
// key cannot reach a log line, an error string or a session report by being
// swept up in a %v, a %#v or a json.Marshal of whatever struct holds it. Code
// that needs the bytes indexes the array, which is deliberate and greppable.
type StaticKey [StaticKeySize]byte

// String returns a fixed placeholder rather than the key. fmt calls this for a
// StaticKey and for a *StaticKey at any nesting depth, so a struct holding one
// prints safely without every printing site having to remember.
func (k StaticKey) String() string { return redactedStaticKey }

// GoString returns the same placeholder as String, because the %#v verb
// bypasses fmt.Stringer and %#v on a profile is exactly what someone debugging
// a parse reaches for.
func (k StaticKey) GoString() string { return redactedStaticKey }

// MarshalJSON encodes the key as the placeholder string, so a report or a dump
// that serialises a profile carries no key material. The result is deliberately
// not decodable back into a key: a key is parsed from its source, never
// restored from something that was serialised.
func (k StaticKey) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(redactedStaticKey)), nil
}

// Encode renders the key as the block "openvpn --genkey" writes, which
// ParseStaticKey reads back to the same bytes. The result is key material.
func (k StaticKey) Encode() []byte {
	const perLine = 16 // bytes per line: 32 hex digits
	var b strings.Builder
	b.Grow(len(staticKeyHeader) + len(staticKeyFooter) + 2 + 2*StaticKeySize + StaticKeySize/perLine)
	b.WriteString(staticKeyHeader)
	b.WriteByte('\n')
	for i := 0; i < StaticKeySize; i += perLine {
		b.WriteString(hex.EncodeToString(k[i : i+perLine]))
		b.WriteByte('\n')
	}
	b.WriteString(staticKeyFooter)
	b.WriteByte('\n')
	return []byte(b.String())
}

// ParseStaticKey parses the body of an OpenVPN static key: the contents of a
// <tls-auth> or <tls-crypt> block, or of the file such a block was inlined
// from.
//
// The accepted form is what "openvpn --genkey" writes: an optional
// "-----BEGIN OpenVPN Static key V1-----" header, 512 hexadecimal digits in any
// line arrangement, and an optional matching footer. Blank lines and '#' or ';'
// comment lines are ignored wherever they appear, since a generated key file
// carries a three-line comment banner above the header.
//
// The returned error names what is wrong and never contains any part of body:
// a malformed key is still key material, and the leading half of a truncated
// tls-auth key is the whole of the send HMAC key.
func ParseStaticKey(body []byte) (*StaticKey, error) {
	digits := make([]byte, 0, 2*StaticKeySize)
	sawHeader, sawFooter := false, false

	for n, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "", strings.HasPrefix(line, "#"), strings.HasPrefix(line, ";"):
			continue
		case strings.EqualFold(line, staticKeyHeader):
			if sawHeader {
				return nil, fmt.Errorf("profile: static key: repeated header on line %d", n+1)
			}
			sawHeader = true
			continue
		case strings.EqualFold(line, staticKeyFooter):
			if sawFooter {
				return nil, fmt.Errorf("profile: static key: repeated footer on line %d", n+1)
			}
			sawFooter = true
			continue
		}
		// Anything else must be key digits. Two keys concatenated into one
		// block would otherwise decode as the first 256 bytes of the pair,
		// silently, so digits after the footer are an error, not surplus.
		if sawFooter {
			return nil, fmt.Errorf("profile: static key: content after the footer, on line %d", n+1)
		}
		for i := 0; i < len(line); i++ {
			if !isHexDigit(line[i]) {
				return nil, fmt.Errorf("profile: static key: line %d is not hexadecimal", n+1)
			}
		}
		digits = append(digits, line...)
	}

	if len(digits) != 2*StaticKeySize {
		return nil, fmt.Errorf("profile: static key: %d hex digits, want %d (%d bytes)",
			len(digits), 2*StaticKeySize, StaticKeySize)
	}

	var k StaticKey
	if _, err := hex.Decode(k[:], digits); err != nil {
		// Unreachable: every digit was checked above, and the count is even.
		// The cause is deliberately dropped — hex.InvalidByteError quotes the
		// offending byte, which is key material.
		return nil, fmt.Errorf("profile: static key: hex decode failed")
	}
	return &k, nil
}

// isHexDigit reports whether c is an ASCII hexadecimal digit in either case.
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// KeyDirection is the --key-direction value: 0, 1, or absent.
//
// Absent is a third behaviour, not a default that happens to be zero. With a
// direction, OpenVPN splits the 256-byte static key into per-direction halves,
// and 0 and 1 differ only in which half authenticates outbound packets and
// which inbound; without one, the whole key is used in both directions.
//
// Reading an absent direction as 0 therefore HMACs with the wrong material, and
// the result is indistinguishable from a client holding the wrong key entirely.
type KeyDirection int

const (
	// KeyDirectionAbsent means the profile carried no key-direction
	// directive: the whole key is used in both directions. It is the zero
	// value, so a profile that never saw the directive reports the right
	// behaviour without the parser setting anything.
	KeyDirectionAbsent KeyDirection = iota
	// KeyDirection0 is "key-direction 0".
	KeyDirection0
	// KeyDirection1 is "key-direction 1".
	KeyDirection1
)

// keyDirectionNames maps each KeyDirection to the name used in reports.
var keyDirectionNames = [...]string{
	KeyDirectionAbsent: "absent",
	KeyDirection0:      "0",
	KeyDirection1:      "1",
}

// String returns "absent", "0" or "1", or a "key-direction(N)" placeholder
// when the value is outside the defined range.
func (d KeyDirection) String() string {
	if d < 0 || int(d) >= len(keyDirectionNames) {
		return "key-direction(" + strconv.Itoa(int(d)) + ")"
	}
	return keyDirectionNames[d]
}

// Value returns the numeric direction and whether the profile gave one. The
// constants are not the numbers they name — the zero value had to be "absent"
// rather than "0" — so int(d) is never the conversion to reach for.
func (d KeyDirection) Value() (int, bool) {
	switch d {
	case KeyDirection0:
		return 0, true
	case KeyDirection1:
		return 1, true
	default:
		return 0, false
	}
}

// ParseKeyDirection parses the argument of a key-direction directive. OpenVPN
// accepts 0 and 1 and nothing else.
func ParseKeyDirection(s string) (KeyDirection, error) {
	switch strings.TrimSpace(s) {
	case "0":
		return KeyDirection0, nil
	case "1":
		return KeyDirection1, nil
	default:
		return KeyDirectionAbsent, fmt.Errorf("profile: key-direction: must be 0 or 1")
	}
}

// MarshalText implements encoding.TextMarshaler. An out-of-range value
// marshals as its String placeholder, which UnmarshalText refuses.
func (d KeyDirection) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, accepting "absent", "0"
// and "1". An unrecognised name is an error.
func (d *KeyDirection) UnmarshalText(text []byte) error {
	name := string(text)
	for i, n := range keyDirectionNames {
		if n == name {
			*d = KeyDirection(i)
			return nil
		}
	}
	return fmt.Errorf("profile: unknown key direction %q", name)
}
