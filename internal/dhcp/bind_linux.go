//go:build linux

package dhcp

import "syscall"

// bindToDevice pins the socket to one interface so a multi-homed Pi does not
// answer DHCP on, say, its Wi-Fi guest network.
func bindToDevice(fd int, iface string) error {
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
}
