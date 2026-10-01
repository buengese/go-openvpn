module github.com/buengese/go-openvpn

go 1.25.5

require (
	github.com/godbus/dbus/v5 v5.2.2
	golang.org/x/sys v0.43.0
	gvisor.dev/gvisor v0.0.0-20260224225140-573d5e7127a8
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	// golang.org/x/mobile is imported by no Go file in this module: gomobile
	// bind requires the module to depend on it all the same. `go mod tidy`
	// therefore drops it; restore it with
	// `go get golang.org/x/mobile@<version>` when it disappears.
	golang.org/x/mobile v0.0.0-20260410095206-2cfb76559b7b // indirect
	golang.org/x/time v0.12.0 // indirect
)
