//go:build !linux && !windows

package dhcp

// bindToDevice is Linux-only; elsewhere the socket stays unbound.
func bindToDevice(fd int, iface string) error { return nil }
