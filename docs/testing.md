# Testing

Eight kinds of test pass, each with one command that says what it costs before
it runs. Nothing is selected by reading a test body: a pass that needs Docker,
root or a build tag says so in its name.

| Kind | Command | Needs | Roughly |
|---|---|---|---|
| unit | `make test` | nothing | seconds |
| acceptance | `make test` | nothing | seconds |
| mockserver | `make test-mock` | nothing (builds a fixture binary) | ~10 s |
| mobileapi | `make test-mobileapi` | nothing | seconds |
| docker | `make test-e2e` | Docker + `make matrix-images` | ~5 min |
| privileged | `make test-privileged` | root | ~1 min |
| soak | `make test-soak SOAK=1h` | Docker | as long as you ask |
| cli | `scripts/cli-integration.sh` | root, the mock server | ~30 s |

`make test` is the default gate and keeps its contract: **no tag, no Docker, no
root, fast.** Every other pass is opt-in, so an untagged run cannot acquire a
dependency by accident.

CI runs `make lint`, `make test` and `make test-mock` — the commands above, not
weaker spellings of them. `go test ./...` and `go vet ./...` alone compile no
tagged file, so for as long as CI ran those instead, every `docker`,
`mockserver`, `privileged`, `soak`, `mobileapi` and `ios` source in the tree
could break without anything noticing, and `golangci-lint` ran nowhere.

## What each pass exercises

**unit** — everything untagged. Protocol primitives against known-answer
vectors, the parser, the capability registry, the report and its redaction, and
`netstack`'s own four test files. A defect here is a defect in one package.

**acceptance** — the suites for the parser, the dial order and the capability
registry. They run under `make test` like everything else, needing nothing, and
they do not skip.

Their fixtures are generated: `caps/fixtures_test.go` and
`profile/fixturedata_test.go` write a profile per structural shape into a
temporary directory from a throwaway PKI on every run.
The shapes instantiate every row in the capability registry, so a regrade moves
a cell in the committed `caps/testdata/registry-matrix.golden` and the diff is
the review's evidence. They also cover how a profile is *written* — CRLF,
comment and blank lines inside inline blocks, an endpoint given as an address,
a directive spelled in a case OpenVPN itself refuses — because a profile is
lexical before it is anything else.

What the suites assert is quantified over configs rather than measured from
one: a wrap key is loaded exactly when an inline block carries one, a file
reference is read or superseded and never both, a dial order is a permutation
of the profile's remotes, and a profile means the same thing whichever way its
lines are terminated.

`caps/testdata/shape-inventory.txt` is the published claim about
what those fixtures cover. It exists so that a holder of a corpus of real
profiles can check it against something: anything such a corpus exercises and
the inventory does not name is a shape these tests have stopped seeing. That
check lives in the tool that holds the corpus, not here.

**mobileapi** — the gomobile surface, `MobileClient` and `MobileCallbacks`. That
file is tagged `android || darwin` so the type stays out of the Linux library's
API, which also kept it out of every test run: the binding shipped with no way
to supply a username and password, and nothing noticed. The tag adds the host to
that list so the surface can be tested where the tests can run. gomobile itself
never sets it, so the shipped `.aar` and xcframework are unaffected. It is the
one opt-in pass `make test` runs anyway, because it needs nothing.

**mockserver** — drives `testenv/mockserver` as a subprocess. It is the AWS Client
VPN CRV1 regression gate and the fastest end-to-end feedback in the tree. No
Docker. The mock carries a data channel and pushes keepalives, so every test
under this tag disconnects from a peer that is still sending — which is what
`TestDisconnectUnderTrafficTearsDownCleanly` needs and what nothing in the tree
did before.

**docker** — real pinned OpenVPN 2.4, 2.5 and 2.6 servers in containers, from
`make matrix-images`. This is where a capability is proved against software we
did not write. Fails with an actionable message if the images are absent.

**privileged** — creates real TUN devices and edits the host route table. Needs
root and `OPENLAWSVPN_PRIVILEGED_TESTS=1`; skips otherwise.

`tun` has no untagged tests at all, and `go test ./tun` reporting *no test
files* is the intended answer rather than a gap: every test in the package
opens `/dev/net/tun`, so all of them are behind the tag. They used to be
untagged and skip themselves one by one, which in the single line `go test`
prints is indistinguishable from three tests that ran.

**soak** — one tunnel held open for hours while renegotiating, and twenty
concurrent ones. Gated behind `OPENLAWSVPN_SOAK` so it can never run by
accident. It is the only pass that asks whether anything is still working
later, which is where a key rotation, a keepalive and a leak live.

**cli** — the built binary, driven as a program: start the mock server, connect
in daemon mode, assert the tunnel comes up, tear it down. CI runs it on Linux
and macOS with and without `--redirect-gateway`.

`cmd/cli` has no Go tests, on purpose. A Go test of a command-line program ends
up compiling a helper binary and spawning it, which is what this script does
properly and in an environment that has root and a TUN device. The package is
argument handling and process plumbing; the logic worth asserting lives in the
library it calls.

## Two decisions worth not re-litigating

**The acceptance suites are untagged and unconditional.** They used to need an
out-of-tree corpus of real provider profiles and skipped without it, which
meant the coverage that mattered most ran on one machine. Generating the
fixtures is what made them ordinary tests; nothing about them is opt-in now.

**`-p 1` on the Docker pass is not negotiable.** `e2e` and `testenv` share two
pieces of global state: the Docker daemon, where `testenv` asserts no stray
containers are left behind, and the host network namespace, where the netstack
tests assert no interface or route changed. Run in parallel, each sees the
other's containers and veth interfaces and fails for a reason that has nothing
to do with the code.

## Where the tests live

    e2e/            every end-to-end test of the client: docker, mockserver, soak
    netstack/       four unit tests of the userspace stack itself
    testenv/        the rig — Docker matrix, reference oracle, mock harness
    caps/           the capability registry, its generated fixtures and the
                    published shape inventory
    <package>/      that package's own unit tests

`e2e` exists because fifteen tests that started real servers had accumulated in
`netstack`, where they were testing the whole client and merely using netstack
as the device backend — it is the only backend that runs unprivileged.

## Lint

`make lint` runs `go vet` once per build tag, plus `golangci-lint`, whose
`build-tags` list must name every tag. The `ios` files need a darwin `GOOS` as
well as the tag, which is the spelling `check-platforms` uses; without it they
were linted by nothing. Both are easy to get wrong in the same
way: a linter pointed at a tag nothing carries silently analyses nothing, and
reads as coverage that does not exist.
