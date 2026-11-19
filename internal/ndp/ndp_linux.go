//go:build linux

package ndp

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// procSys is the sysctl root; tests may point it elsewhere.
var procSys = "/proc/sys"

// Open enables proxy NDP on iface and returns a cache that installs
// proxy-neighbor entries on it through rtnetlink, the equivalent of
// `ip -6 neigh replace proxy <addr> dev <iface>`.
//
// The kernel only answers solicitations for proxy entries on an interface
// that also has IPv6 forwarding enabled, so Open refuses to start when
// net.ipv6.conf.<iface>.forwarding is 0 instead of silently doing nothing.
func Open(iface string, maxEntries int) (*Cache, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("ndp-proxy interface %q: %w", iface, err)
	}
	forwarding, err := readSysctl("net/ipv6/conf/" + iface + "/forwarding")
	if err != nil {
		return nil, err
	}
	if forwarding == "0" {
		return nil, fmt.Errorf("ndp-proxy: net.ipv6.conf.%s.forwarding is 0, and the kernel ignores proxy NDP entries on non-forwarding interfaces; "+
			"set net.ipv6.conf.%s.forwarding=1 (and net.ipv6.conf.%s.accept_ra=2 if the interface learns its default route from router advertisements)",
			iface, iface, iface)
	}
	if err := writeSysctl("net/ipv6/conf/"+iface+"/proxy_ndp", "1"); err != nil {
		return nil, err
	}

	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("ndp-proxy: open netlink handle: %w", err)
	}
	index := link.Attrs().Index
	neigh := func(addr netip.Addr) *netlink.Neigh {
		return &netlink.Neigh{
			LinkIndex: index,
			Family:    netlink.FAMILY_V6,
			Flags:     netlink.NTF_PROXY,
			IP:        net.IP(addr.AsSlice()),
		}
	}
	install := func(addr netip.Addr) error { return handle.NeighSet(neigh(addr)) }
	remove := func(addr netip.Addr) error {
		err := handle.NeighDel(neigh(addr))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	cache, err := NewCache(maxEntries, install, remove)
	if err != nil {
		handle.Close()
		return nil, err
	}
	cache.onClose = func() error {
		handle.Close()
		return nil
	}
	slog.Info("Proxy NDP enabled", "interface", iface, "max_entries", maxEntries)
	return cache, nil
}

func readSysctl(key string) (string, error) {
	data, err := os.ReadFile(procSys + "/" + key)
	if err != nil {
		return "", fmt.Errorf("ndp-proxy: read sysctl %s: %w", strings.ReplaceAll(key, "/", "."), err)
	}
	return strings.TrimSpace(string(data)), nil
}

func writeSysctl(key, value string) error {
	if err := os.WriteFile(procSys+"/"+key, []byte(value), 0o644); err != nil {
		return fmt.Errorf("ndp-proxy: set sysctl %s=%s: %w", strings.ReplaceAll(key, "/", "."), value, err)
	}
	return nil
}
