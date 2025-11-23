package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf xdp xdp.c

import (
	"fmt"
	"log"
	"net"
	"flag"
	"os"
	"context"
	"os/signal"
	"strings"
	"syscall"
	"encoding/binary"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Builds keys for BPF_MAP_TYPE_LPM_TRIE eBPF map from the input CIDRs
func buildIPv4LPMKeys(blockedIPs string) ([]xdpIpv4LpmKey, error) {
	blockedIPs = strings.TrimSpace(blockedIPs)
	if blockedIPs == "" {
		return nil, fmt.Errorf("--blocked-ips is required")
	}

	var keys []xdpIpv4LpmKey
	for _, s := range strings.Split(blockedIPs, ",") {
		s = strings.TrimSpace(s)
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}

		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("not an IPv4 address %q", s)
		}

		maskLen, _ := ipNet.Mask.Size()

		keys = append(keys, xdpIpv4LpmKey{
			Prefixlen: uint32(maskLen),
			// Convert (e.g. [127 0 0 1]) to a uint32 by interpreting the bytes in network byte order (big-endian) 
			// as expected by the kernel program
			Data:      binary.BigEndian.Uint32(ip4),
		})
	}

	return keys, nil
}

func main() {
	var ifname       string
	var blockedIPs   string
	flag.StringVar(&ifname, "i", "lo", "Network interface name where the eBPF programs will be attached")
	flag.StringVar(&blockedIPs, "blocked-ips", "", "Comma-separated IP/mask (192.168.23.3/32, 228.13.0.0/16)")
	flag.Parse()

	// Builds the keys for the BPF_MAP_TYPE_LPM_TRIE eBPF Map
	// e.g. 127.0.0.1/32 -> { Prefixlen: 32, Data: 16777343} 
	// Where the:
	// - 'Prefixlen' is the prefix length in bits (e.g., /32, /24).
	// - 'Data' is the IP converted to the integer (big-endian order)
	keys, err := buildIPv4LPMKeys(blockedIPs)
	if err != nil {
		log.Fatalf("blocked-ips error: %v", err)
	}

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs xdpObjects
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Add blocked CIDRs/LPM Trie keys into the eBPF map
	// Doesn't matter which prefix the captured IP will match (as long as it does match we need to block it)
	for _, key := range keys {
		if err := objs.xdpMaps.BlockedIps.Put(&key, uint32(1)); err != nil {
			log.Fatalf("error adding CIDR to allow list: %s", err)
		}
	}

	// Attach XDP program to the network interface.
	xdplink, err := link.AttachXDP(link.XDPOptions{
				Program:   objs.XdpProgram,
				Interface: iface.Index,
				Flags: link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()
	fmt.Println("XDP program successfully attached. Press Enter to exit.")

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	<-ctx.Done()
	log.Println("Received signal, exiting...")
}
