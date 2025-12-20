package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketEvent struct {
	Time        string `json:"time"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Length      int    `json:"length"`
	Info        string `json:"info"`
}

var (
	iface   = flag.String("i", "", "Interface name to capture (use --list to list)")
	port    = flag.Int("port", 4000, "HTTP port for SSE")
	listIFs = flag.Bool("list", false, "List available pcap devices")
)

func listDevices() {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Failed to list devices: %v", err)
	}
	for _, d := range devs {
		fmt.Printf("Name: %s\n", d.Name)
		if d.Description != "" {
			fmt.Printf("  Desc: %s\n", d.Description)
		}
		for _, a := range d.Addresses {
			fmt.Printf("  Addr: %s\n", a.IP)
		}
		fmt.Println()
	}
}

func main() {
	flag.Parse()
	if *listIFs {
		listDevices()
		return
	}
	if *iface == "" {
		log.Fatalf("Interface required. Use -i <iface> or --list to enumerate interfaces.")
	}

	// verify interface exists
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("pcap.FindAllDevs error: %v", err)
	}
	found := false
	for _, d := range ifaces {
		if d.Name == *iface || strings.Contains(d.Name, *iface) || strings.Contains(d.Description, *iface) {
			found = true
			break
		}
	}
	if !found {
		log.Printf("Warning: interface '%s' not found in devices. Continuing and letting pcap try to open it.", *iface)
	}

	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// open pcap handle
		handle, err := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
		if err != nil {
			log.Printf("pcap.OpenLive error: %v", err)
			msg := map[string]string{"error": fmt.Sprintf("pcap open failed: %v", err)}
			b, _ := json.Marshal(msg)
			fmt.Fprintf(w, "data: %s\n\n", b)
			return
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		ch := packetSource.Packets()

		notify := w.(http.CloseNotifier).CloseNotify()
		for {
			select {
			case <-notify:
				log.Println("Client disconnected from SSE")
				return
			case p, ok := <-ch:
				if !ok {
					log.Println("packet channel closed")
					return
				}
				pe := PacketEvent{Time: time.Now().Format(time.RFC3339Nano), Length: len(p.Data())}
				if net := p.NetworkLayer(); net != nil {
					src, dst := net.NetworkFlow().Endpoints()
					pe.Source = src.String()
					pe.Destination = dst.String()
				}
				if tr := p.TransportLayer(); tr != nil {
					pe.Protocol = tr.LayerType().String()
				} else if app := p.ApplicationLayer(); app != nil {
					pe.Protocol = app.LayerType().String()
				} else if p.Layer(layers.LayerTypeIPv4) != nil {
					pe.Protocol = "IPv4"
				}
				// simple info for TCP/UDP ports
				if tcp := p.Layer(layers.LayerTypeTCP); tcp != nil {
					t := tcp.(*layers.TCP)
					pe.Info = fmt.Sprintf("%d → %d", t.SrcPort, t.DstPort)
				} else if udp := p.Layer(layers.LayerTypeUDP); udp != nil {
					u := udp.(*layers.UDP)
					pe.Info = fmt.Sprintf("%d → %d", u.SrcPort, u.DstPort)
				}

				b, _ := json.Marshal(pe)
				fmt.Fprintf(w, "data: %s\n\n", b)
				// flush
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}
	})

	// graceful shutdown on Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Shutting down capture server")
		os.Exit(0)
	}()

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting Go capture server on %s (iface=%s)", addr, *iface)
	log.Fatal(http.ListenAndServe(addr, nil))
}
