package main

import (
	"fmt"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestTypeString(t *testing.T) {
	tests := []struct {
		input    layers.DNSType
		expected string
	}{
		{layers.DNSTypeA, "A"},
		{layers.DNSTypeNS, "NS"},
		{layers.DNSTypeMD, "MD"},
		{layers.DNSTypeMF, "MF"},
		{layers.DNSTypeCNAME, "CNAME"},
		{layers.DNSTypeSOA, "SOA"},
		{layers.DNSTypeMB, "MB"},
		{layers.DNSTypeMG, "MG"},
		{layers.DNSTypeMR, "MR"},
		{layers.DNSTypeNULL, "NULL"},
		{layers.DNSTypeWKS, "WKS"},
		{layers.DNSTypePTR, "PTR"},
		{layers.DNSTypeHINFO, "HINFO"},
		{layers.DNSTypeMINFO, "MINFO"},
		{layers.DNSTypeMX, "MX"},
		{layers.DNSTypeTXT, "TXT"},
		{layers.DNSTypeAAAA, "AAAA"},
		{layers.DNSTypeSRV, "SRV"},
		{layers.DNSTypeOPT, "OPT"},
		{layers.DNSTypeURI, "URI"},
		{layers.DNSType(255), "ANY"},
		{layers.DNSType(999), "999"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := TypeString(tt.input)
			if result != tt.expected {
				t.Fatalf("TypeString(%d) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRrString(t *testing.T) {
	t.Run("A", func(t *testing.T) {
		rr := layers.DNSResourceRecord{Type: layers.DNSTypeA, IP: net.ParseIP("1.2.3.4")}
		if got := RrString(rr); got != "1.2.3.4" {
			t.Fatalf("got %s, want 1.2.3.4", got)
		}
	})

	t.Run("AAAA", func(t *testing.T) {
		rr := layers.DNSResourceRecord{Type: layers.DNSTypeAAAA, IP: net.ParseIP("::1")}
		if got := RrString(rr); got != "::1" {
			t.Fatalf("got %s, want ::1", got)
		}
	})

	t.Run("CNAME", func(t *testing.T) {
		rr := layers.DNSResourceRecord{Type: layers.DNSTypeCNAME, CNAME: []byte("www.example.com")}
		if got := RrString(rr); got != "www.example.com" {
			t.Fatalf("got %s, want www.example.com", got)
		}
	})

	t.Run("MX", func(t *testing.T) {
		rr := layers.DNSResourceRecord{
			Type: layers.DNSTypeMX,
			MX:   layers.DNSMX{Preference: 10, Name: []byte("mail.example.com")},
		}
		if got := RrString(rr); got != "10 mail.example.com" {
			t.Fatalf("got %s, want 10 mail.example.com", got)
		}
	})

	t.Run("NS", func(t *testing.T) {
		rr := layers.DNSResourceRecord{Type: layers.DNSTypeNS, NS: []byte("ns1.example.com")}
		if got := RrString(rr); got != "ns1.example.com" {
			t.Fatalf("got %s, want ns1.example.com", got)
		}
	})

	t.Run("PTR", func(t *testing.T) {
		rr := layers.DNSResourceRecord{Type: layers.DNSTypePTR, PTR: []byte("host.example.com")}
		if got := RrString(rr); got != "host.example.com" {
			t.Fatalf("got %s, want host.example.com", got)
		}
	})

	t.Run("TXT", func(t *testing.T) {
		rr := layers.DNSResourceRecord{Type: layers.DNSTypeTXT, TXT: []byte("v=spf1 include:example.com")}
		if got := RrString(rr); got != "v=spf1 include:example.com" {
			t.Fatalf("got %s", got)
		}
	})

	t.Run("SOA", func(t *testing.T) {
		rr := layers.DNSResourceRecord{
			Type: layers.DNSTypeSOA,
			SOA: layers.DNSSOA{
				MName:   []byte("ns1.example.com"),
				RName:   []byte("admin.example.com"),
				Serial:  2024010100,
				Refresh: 3600,
				Retry:   900,
				Expire:  604800,
				Minimum: 86400,
			},
		}
		expected := fmt.Sprintf("ns1.example.com admin.example.com %d %d %d %d %d",
			2024010100, 3600, 900, 604800, 86400)
		if got := RrString(rr); got != expected {
			t.Fatalf("got %s, want %s", got, expected)
		}
	})

	t.Run("SRV", func(t *testing.T) {
		rr := layers.DNSResourceRecord{
			Type: layers.DNSTypeSRV,
			SRV: layers.DNSSRV{
				Priority: 10,
				Weight:   20,
				Port:     443,
				Name:     []byte("svc.example.com"),
			},
		}
		if got := RrString(rr); got != "10 20 443 svc.example.com" {
			t.Fatalf("got %s", got)
		}
	})

	t.Run("URI", func(t *testing.T) {
		rr := layers.DNSResourceRecord{Type: layers.DNSTypeURI, Data: []byte("https://example.com")}
		if got := RrString(rr); got != "https://example.com" {
			t.Fatalf("got %s", got)
		}
	})

	t.Run("OPT", func(t *testing.T) {
		rr := layers.DNSResourceRecord{Type: layers.DNSTypeOPT, Data: []byte("optdata")}
		if got := RrString(rr); got != "optdata" {
			t.Fatalf("got %s", got)
		}
	})

	t.Run("Unknown", func(t *testing.T) {
		rr := layers.DNSResourceRecord{Type: layers.DNSType(999), Data: []byte("rawdata")}
		if got := RrString(rr); got != "rawdata" {
			t.Fatalf("got %s", got)
		}
	})
}

func TestFoundLayerType(t *testing.T) {
	found := []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeDNS}

	if !foundLayerType(layers.LayerTypeIPv4, found) {
		t.Fatal("expected to find IPv4")
	}
	if !foundLayerType(layers.LayerTypeDNS, found) {
		t.Fatal("expected to find DNS")
	}
	if foundLayerType(layers.LayerTypeTCP, found) {
		t.Fatal("did not expect to find TCP")
	}
	if foundLayerType(layers.LayerTypeUDP, []gopacket.LayerType{}) {
		t.Fatal("did not expect to find UDP in empty slice")
	}
}
