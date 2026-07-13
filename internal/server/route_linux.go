//go:build linux

package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// routeTableLocal is the Linux local routing table ID.
const routeTableLocal = 255

// routePriority is the priority for routes added by outway.
const routePriority = 1024

func init() {
	configureRoutes = configureRoutesLinux
	validateSourceCIDR = validateSourceCIDRLinux
}

func validateSourceCIDRLinux(cidr netip.Prefix) error {
	address := cidr.Masked().Addr()
	if next := address.Next(); next.IsValid() && cidr.Contains(next) {
		address = next
	}
	ip := net.IP(address.AsSlice())

	tcpNetwork := "tcp4"
	udpNetwork := "udp4"
	if address.Is6() {
		tcpNetwork = "tcp6"
		udpNetwork = "udp6"
	}
	tcpListener, err := net.ListenTCP(tcpNetwork, &net.TCPAddr{IP: ip, Port: 0})
	if err != nil {
		return fmt.Errorf("bind TCP source address %s: %w", address, err)
	}
	if err := tcpListener.Close(); err != nil {
		return fmt.Errorf("close TCP source-address probe: %w", err)
	}

	udpListener, err := net.ListenUDP(udpNetwork, &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		return fmt.Errorf("bind UDP source address %s: %w", address, err)
	}
	if err := udpListener.Close(); err != nil {
		return fmt.Errorf("close UDP source-address probe: %w", err)
	}
	slog.Info("Validated source CIDR binding", "cidr", cidr, "address", address)
	return nil
}

// configureRoutesLinux configures sysctls and routes for the given CIDR on
// Linux: enables IPv6 non-local bind, enables IPv6 globally, and adds a local
// route for the CIDR to the loopback interface.
func configureRoutesLinux(cidr netip.Prefix) error {
	if cidr.Addr().Is6() {
		if err := sysctlSet("net.ipv6.ip_nonlocal_bind", "1"); err != nil {
			return err
		}
		if err := sysctlSet("net.ipv6.conf.all.disable_ipv6", "0"); err != nil {
			return err
		}
	}
	if err := addRouteToLoopback(cidr); err != nil {
		return err
	}
	return nil
}

// sysctlSet writes a value to a sysctl key via /proc/sys.
func sysctlSet(key, value string) error {
	path := "/proc/sys/" + keyToPath(key)
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("set sysctl %s=%s: %w", key, value, err)
	}
	slog.Debug("Configured sysctl", "key", key, "value", value)
	return nil
}

// keyToPath converts a dotted sysctl key to a /proc/sys path.
func keyToPath(key string) string {
	path := make([]byte, 0, len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c == '.' {
			path = append(path, '/')
		} else {
			path = append(path, c)
		}
	}
	return string(path)
}

// addRouteToLoopback adds a local route for the CIDR to the loopback
// interface using netlink (rtnetlink).
func addRouteToLoopback(cidr netip.Prefix) error {
	// Get the loopback interface.
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("get loopback interface: %w", err)
	}

	// Convert netip.Prefix to *net.IPNet for netlink.
	dstNet := prefixToIPNet(cidr)

	// Check if the route already exists.
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
		Table: routeTableLocal,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}

	for _, r := range routes {
		if r.Dst != nil && ipNetEqual(r.Dst, dstNet) {
			slog.Info(fmt.Sprintf("Route %s already exists on loopback interface", cidr))
			return nil
		}
	}

	// Add the route.
	route := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Dst:       dstNet,
		Type:      unix.RTN_LOCAL,
		Protocol:  unix.RTPROT_BOOT,
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Table:     routeTableLocal,
		Priority:  routePriority,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("add route: %w", err)
	}
	slog.Info(fmt.Sprintf("Added route %s to loopback interface", cidr))
	return nil
}

// prefixToIPNet converts a netip.Prefix to a *net.IPNet.
func prefixToIPNet(p netip.Prefix) *net.IPNet {
	ip := net.IP(p.Addr().AsSlice())
	mask := net.CIDRMask(p.Bits(), p.Addr().BitLen())
	return &net.IPNet{IP: ip, Mask: mask}
}

// ipNetEqual reports whether two *net.IPNet values are equal.
func ipNetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IP.Equal(b.IP) && bytesEqual(a.Mask, b.Mask)
}

// bytesEqual reports whether two byte slices are equal.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
