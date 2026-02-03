package main

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNewTcpData(t *testing.T) {
	td := tcpDataStruct{
		DnsData: []byte{1, 2, 3},
		Length:  3,
	}
	pd := NewTcpData(td)
	if pd.datatype != "tcp" {
		t.Fatalf("datatype = %s, want tcp", pd.datatype)
	}
	if !pd.IsTCPStream() {
		t.Fatal("IsTCPStream() should be true for tcp data")
	}
}

func TestNewPacketData(t *testing.T) {
	packetSource := getPacketData("a")
	if packetSource == nil {
		t.Fatal("Failed to open pcap")
	}
	packet := <-packetSource.Packets()
	pd := NewPacketData(packet)
	if pd.datatype != "packet" {
		t.Fatalf("datatype = %s, want packet", pd.datatype)
	}
	if pd.IsTCPStream() {
		t.Fatal("IsTCPStream() should be false for packet data")
	}
}

func TestPacketDataParseUDP(t *testing.T) {
	packetSource := getPacketData("a")
	packet := <-packetSource.Packets()
	pd := NewPacketData(packet)

	err := pd.Parse()
	if err != nil {
		t.Fatalf("Parse() failed: %s", err)
	}

	if pd.GetIPLayer() == nil {
		t.Fatal("GetIPLayer() returned nil")
	}
	if pd.GetSrcIP() == nil {
		t.Fatal("GetSrcIP() returned nil")
	}
	if pd.GetDstIP() == nil {
		t.Fatal("GetDstIP() returned nil")
	}
	if pd.GetTimestamp() == nil {
		t.Fatal("GetTimestamp() returned nil for packet")
	}
	if pd.GetSize() == nil {
		t.Fatal("GetSize() returned nil")
	}
	if pd.GetProto() == nil || *pd.GetProto() != "packet" {
		t.Fatalf("GetProto() = %v, want 'packet'", pd.GetProto())
	}
}

func TestPacketDataParseTCP(t *testing.T) {
	// Create a minimal DNS payload for TCP data
	dnsBytes := makeDNSQueryBytes()
	td := tcpDataStruct{
		DnsData: dnsBytes,
		Length:  len(dnsBytes),
	}
	pd := NewTcpData(td)

	err := pd.Parse()
	if err != nil {
		t.Fatalf("Parse() failed: %s", err)
	}

	if pd.GetDNSLayer() == nil {
		t.Fatal("GetDNSLayer() returned nil for tcp data")
	}
	if pd.GetTimestamp() != nil {
		t.Fatal("GetTimestamp() should be nil for tcp data")
	}
	sz := pd.GetSize()
	if sz == nil || *sz != 0 {
		t.Fatalf("GetSize() for tcp should be 0, got %v", sz)
	}
	proto := pd.GetProto()
	if proto == nil || *proto != "tcp" {
		t.Fatalf("GetProto() for tcp data should be 'tcp', got %v", proto)
	}
}

func TestPacketDataParseBadType(t *testing.T) {
	pd := &packetData{datatype: "invalid"}
	err := pd.Parse()
	if err == nil {
		t.Fatal("Parse() should fail for invalid datatype")
	}
}

func TestPacketDataHasLayers(t *testing.T) {
	packetSource := getPacketData("a")
	// Get the DNS response packet (second packet)
	<-packetSource.Packets() // skip query
	packet := <-packetSource.Packets()
	pd := NewPacketData(packet)
	pd.Parse()

	if !pd.HasIPLayer() {
		t.Fatal("expected HasIPLayer() == true")
	}
	if !pd.HasDNSLayer() {
		t.Fatal("expected HasDNSLayer() == true for DNS response")
	}
}

func TestPacketDataGetTCPLayer(t *testing.T) {
	// For a UDP packet, TCP layer should be nil
	packetSource := getPacketData("a")
	packet := <-packetSource.Packets()
	pd := NewPacketData(packet)
	pd.Parse()

	if pd.HasTCPLayer() {
		t.Fatal("UDP packet should not have TCP layer")
	}
}

// helper to create a minimal DNS query as bytes
func makeDNSQueryBytes() []byte {
	dns := &layers.DNS{
		ID:      0x1234,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	dns.SerializeTo(buf, opts)
	return buf.Bytes()
}
