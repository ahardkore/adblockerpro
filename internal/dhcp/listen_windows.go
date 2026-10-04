//go:build windows

package dhcp

import (
	"context"
	"errors"
	"net"
)

// listenDHCP is not supported on Windows; adblockerpro targets Linux (the
// Raspberry Pi), and this stub only exists so the package still builds.
func listenDHCP(ctx context.Context, iface string) (net.PacketConn, error) {
	return nil, errors.New("dhcp: the DHCP server is only supported on Unix hosts")
}
