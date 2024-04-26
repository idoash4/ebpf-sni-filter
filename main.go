package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Domain represents a blocked domain
type Domain struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

// ReadBlockedDomains reads blocked domains from a JSON file
func ReadBlockedDomains(filename string) ([]Domain, error) {
	// Open the JSON file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Decode JSON data
	var domains []Domain
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&domains); err != nil {
		return nil, err
	}

	return domains, nil
}

func main() {
	// Make sure an interface is specified and domains list file is provided.
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <iface> <domains-list-file>", os.Args[0])
	}

	// Read the blocked domains from the JSON file.
	blockedDomains, err := ReadBlockedDomains(os.Args[2])
	if err != nil {
		fmt.Printf("Error reading blocked domains: %s\n", err)
		return
	}

	// Check if the number of domains is within the limit.
	if len(blockedDomains) > 256 {
		log.Fatalf("Too many domains, max 256 allowed")
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs filter_sniObjects
	if err := loadFilter_sniObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	// Close on exit.
	defer objs.Close()

	// Get the network interface by name.
	ifname := os.Args[1]
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach filter_sni to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.FilterSni,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	// Close on exit.
	defer link.Close()

	// Add the domains to the map.
	for _, domain := range blockedDomains {
		// Convert the domain name to a fixed-size byte array of 256 bytes
		var domainKey [256]byte
		copy(domainKey[:], domain.Domain)
		err = objs.DomainNames.Put(domainKey, uint64(0))
		if err != nil {
			log.Fatal("Failed adding domain to map:", err)
		}
	}

	// Periodically fetch the dropped packet counter.
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Dropped %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			// Print the count for each domain.
			for _, domain := range blockedDomains {
				// Convert the domain name to a fixed-size byte array of 256 bytes
				var domainKey [256]byte
				var count uint64
				copy(domainKey[:], domain.Domain)
				err = objs.DomainNames.Lookup(domainKey, &count)
				if err != nil {
					log.Fatal("Failed finding domain in map:", err)
				}
				log.Printf("Domain %s: %d packets dropped", domain.Domain, count)
			}
			return
		}
	}
}
