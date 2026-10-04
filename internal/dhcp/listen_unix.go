//go:build !windows

package dhcp

import (
	"context"
	"net"
	"syscall"
)

// listenDHCP binds UDP/67 with SO_BROADCAST (and SO_REUSEADDR) set, which a
// DHCP server needs in order to answer clients that have no address yet.
func listenDHCP(ctx context.Context, iface string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
					ctrlErr = err
					return
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					ctrlErr = err
					return
				}
				if iface != "" {
					// Best effort: keep serving if the kernel refuses
					// (needs CAP_NET_RAW on some systems).
					_ = bindToDevice(int(fd), iface)
				}
			})
			if err != nil {
				return err
			}
			return ctrlErr
		},
	}
	return lc.ListenPacket(ctx, "udp4", ":67")
}
