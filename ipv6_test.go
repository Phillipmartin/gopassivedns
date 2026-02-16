package main

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// buildIPv6UDPDNSPacket constructs a raw Ethernet+IPv6+UDP+DNS packet for testing.
func buildIPv6UDPDNSPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, dns *layers.DNS) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip6, udp, dns)
	return buf.Bytes()
}

// buildIPv6TCPDNSPacket constructs a raw Ethernet+IPv6+TCP packet for testing.
func buildIPv6TCPDNSPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		HopLimit:   64,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip6, tcp)
	return buf.Bytes()
}

// parseTestPacket parses raw bytes into a gopacket.Packet with Ethernet decoding.
func parseTestPacket(data []byte) gopacket.Packet {
	return gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
}

// --- packetData tests for IPv6 ---

func TestPacketDataParseIPv6UDP(t *testing.T) {
	clientIP := net.ParseIP("2001:db8::1")
	serverIP := net.ParseIP("2001:4860:4860::8888")

	dnsQuery := &layers.DNS{
		ID:      0xABCD,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
	}
	raw := buildIPv6UDPDNSPacket(clientIP, serverIP, 12345, 53, dnsQuery)
	packet := parseTestPacket(raw)
	pd := NewPacketData(packet)

	err := pd.Parse()
	if err != nil {
		t.Fatalf("Parse() failed: %s", err)
	}

	if !pd.HasIPLayer() {
		t.Fatal("HasIPLayer() should be true for IPv6 packet")
	}
	if !pd.HasIPv6Layer() {
		t.Fatal("HasIPv6Layer() should be true")
	}
	if pd.HasIPv4Layer() {
		t.Fatal("HasIPv4Layer() should be false for IPv6 packet")
	}
	if !pd.HasDNSLayer() {
		t.Fatal("HasDNSLayer() should be true")
	}
	if pd.HasTCPLayer() {
		t.Fatal("HasTCPLayer() should be false for UDP packet")
	}

	srcIP := pd.GetSrcIP()
	if !srcIP.Equal(clientIP) {
		t.Fatalf("GetSrcIP() = %s, want %s", srcIP, clientIP)
	}
	dstIP := pd.GetDstIP()
	if !dstIP.Equal(serverIP) {
		t.Fatalf("GetDstIP() = %s, want %s", dstIP, serverIP)
	}

	if pd.GetIP6Layer() == nil {
		t.Fatal("GetIP6Layer() returned nil")
	}
	if pd.GetDNSLayer() == nil {
		t.Fatal("GetDNSLayer() returned nil")
	}

	flow := pd.GetNetworkFlow()
	if flow.EndpointType() != layers.EndpointIPv6 {
		t.Fatalf("GetNetworkFlow() endpoint type = %v, want IPv6", flow.EndpointType())
	}
}

func TestPacketDataParseIPv6TCP(t *testing.T) {
	srcIP := net.ParseIP("fe80::1")
	dstIP := net.ParseIP("fe80::2")

	raw := buildIPv6TCPDNSPacket(srcIP, dstIP, 54321, 53)
	packet := parseTestPacket(raw)
	pd := NewPacketData(packet)

	err := pd.Parse()
	if err != nil {
		t.Fatalf("Parse() failed: %s", err)
	}

	if !pd.HasIPv6Layer() {
		t.Fatal("HasIPv6Layer() should be true")
	}
	if !pd.HasTCPLayer() {
		t.Fatal("HasTCPLayer() should be true")
	}
	if pd.HasIPv4Layer() {
		t.Fatal("HasIPv4Layer() should be false")
	}

	flow := pd.GetNetworkFlow()
	if flow.EndpointType() != layers.EndpointIPv6 {
		t.Fatalf("GetNetworkFlow() endpoint type = %v, want IPv6", flow.EndpointType())
	}
}

func TestPacketDataIPv6GetSrcDstIP(t *testing.T) {
	tests := []struct {
		name   string
		srcIP  string
		dstIP  string
	}{
		{"global unicast", "2001:db8::1", "2001:db8::2"},
		{"link-local", "fe80::1", "fe80::2"},
		{"loopback", "::1", "::1"},
		{"mapped IPv4", "::ffff:192.168.1.1", "::ffff:10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := net.ParseIP(tt.srcIP)
			dst := net.ParseIP(tt.dstIP)
			dnsQ := &layers.DNS{
				ID: 0x1234, QR: false, OpCode: layers.DNSOpCodeQuery, QDCount: 1,
				Questions: []layers.DNSQuestion{
					{Name: []byte("test.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
				},
			}
			raw := buildIPv6UDPDNSPacket(src, dst, 10000, 53, dnsQ)
			packet := parseTestPacket(raw)
			pd := NewPacketData(packet)
			pd.Parse()

			gotSrc := pd.GetSrcIP()
			gotDst := pd.GetDstIP()
			if !gotSrc.Equal(src) {
				t.Fatalf("GetSrcIP() = %s, want %s", gotSrc, src)
			}
			if !gotDst.Equal(dst) {
				t.Fatalf("GetDstIP() = %s, want %s", gotDst, dst)
			}
		})
	}
}

// --- handleDns tests for IPv6 packets ---

func TestHandleDnsIPv6QueryResponse(t *testing.T) {
	conntable := &connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	logC := make(chan dnsLogEntry, 10)

	clientIP := net.ParseIP("2001:db8::1")
	serverIP := net.ParseIP("2001:4860:4860::8888")

	// Send query
	question := &layers.DNS{
		ID: 0x5678, QR: false, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{Name: []byte("ipv6.example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
	}
	sz := 100
	proto := "udp"
	handleDns(conntable, question, logC, "INFO",
		clientIP, "12345", "53", serverIP, &sz, &proto, time.Now(), nil)

	// Send response
	answer := &layers.DNS{
		ID: 0x5678, QR: true, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{Name: []byte("ipv6.example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
		Answers: []layers.DNSResourceRecord{
			{Type: layers.DNSTypeAAAA, IP: net.ParseIP("2607:f8b0:4001:c02::93"), TTL: 300},
		},
	}
	handleDns(conntable, answer, logC, "INFO",
		serverIP, "53", "12345", clientIP, &sz, &proto, time.Now(), nil)

	select {
	case entry := <-logC:
		if entry.Question != "ipv6.example.com" {
			t.Fatalf("Question = %s, want ipv6.example.com", entry.Question)
		}
		if entry.Question_Type != "AAAA" {
			t.Fatalf("Question_Type = %s, want AAAA", entry.Question_Type)
		}
		if entry.Answer != "2607:f8b0:4001:c02::93" {
			t.Fatalf("Answer = %s, want 2607:f8b0:4001:c02::93", entry.Answer)
		}
		if entry.Answer_Type != "AAAA" {
			t.Fatalf("Answer_Type = %s, want AAAA", entry.Answer_Type)
		}
		if !entry.Server.Equal(serverIP) {
			t.Fatalf("Server = %s, want %s", entry.Server, serverIP)
		}
		if !entry.Client.Equal(clientIP) {
			t.Fatalf("Client = %s, want %s", entry.Client, clientIP)
		}
		if entry.TTL != 300 {
			t.Fatalf("TTL = %d, want 300", entry.TTL)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("No log entry received for IPv6 query/response")
	}
}

func TestHandleDnsIPv6MultipleAnswers(t *testing.T) {
	conntable := &connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	logC := make(chan dnsLogEntry, 10)

	clientIP := net.ParseIP("2001:db8::10")
	serverIP := net.ParseIP("2001:4860:4860::8844")

	question := &layers.DNS{
		ID: 0x9999, QR: false, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{Name: []byte("multi.v6.example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
	}
	sz := 200
	proto := "udp"
	handleDns(conntable, question, logC, "INFO",
		clientIP, "33333", "53", serverIP, &sz, &proto, time.Now(), nil)

	answer := &layers.DNS{
		ID: 0x9999, QR: true, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{Name: []byte("multi.v6.example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
		Answers: []layers.DNSResourceRecord{
			{Type: layers.DNSTypeAAAA, IP: net.ParseIP("2001:db8::100"), TTL: 60},
			{Type: layers.DNSTypeAAAA, IP: net.ParseIP("2001:db8::200"), TTL: 60},
			{Type: layers.DNSTypeAAAA, IP: net.ParseIP("2001:db8::300"), TTL: 60},
		},
	}
	handleDns(conntable, answer, logC, "INFO",
		serverIP, "53", "33333", clientIP, &sz, &proto, time.Now(), nil)

	var entries []dnsLogEntry
	timeout := time.After(2 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case entry := <-logC:
			entries = append(entries, entry)
		case <-timeout:
			t.Fatalf("Expected 3 log entries, got %d", len(entries))
		}
	}

	if len(entries) != 3 {
		t.Fatalf("Expected 3 entries, got %d", len(entries))
	}

	expectedIPs := []string{"2001:db8::100", "2001:db8::200", "2001:db8::300"}
	for i, entry := range entries {
		if entry.Answer != expectedIPs[i] {
			t.Fatalf("entries[%d].Answer = %s, want %s", i, entry.Answer, expectedIPs[i])
		}
		if entry.Answer_Type != "AAAA" {
			t.Fatalf("entries[%d].Answer_Type = %s, want AAAA", i, entry.Answer_Type)
		}
	}
}

func TestHandleDnsIPv6NXDOMAIN(t *testing.T) {
	conntable := &connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	logC := make(chan dnsLogEntry, 10)

	clientIP := net.ParseIP("fd00::1")
	serverIP := net.ParseIP("fd00::53")

	question := &layers.DNS{
		ID: 0xAAAA, QR: false, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{Name: []byte("nxdomain.v6.test"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
	}
	sz := 80
	proto := "udp"
	handleDns(conntable, question, logC, "INFO",
		clientIP, "44444", "53", serverIP, &sz, &proto, time.Now(), nil)

	reply := &layers.DNS{
		ID: 0xAAAA, QR: true, OpCode: layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNXDomain,
		Questions: []layers.DNSQuestion{
			{Name: []byte("nxdomain.v6.test"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
	}
	handleDns(conntable, reply, logC, "INFO",
		serverIP, "53", "44444", clientIP, &sz, &proto, time.Now(), nil)

	select {
	case entry := <-logC:
		if entry.Response_Code != 3 {
			t.Fatalf("Response_Code = %d, want 3 (NXDOMAIN)", entry.Response_Code)
		}
		if entry.Question != "nxdomain.v6.test" {
			t.Fatalf("Question = %s, want nxdomain.v6.test", entry.Question)
		}
		if entry.Answer != "Non-Existent Domain" {
			t.Fatalf("Answer = %s, want Non-Existent Domain", entry.Answer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("No log entry received for IPv6 NXDOMAIN")
	}
}

// --- Concurrent IPv6 handleDns test ---

func TestHandleDnsIPv6Concurrent(t *testing.T) {
	conntable := &connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	logC := make(chan dnsLogEntry, 500)

	const numQueries = 50
	done := make(chan struct{})
	go func() {
		for i := 0; i < numQueries; i++ {
			dnsID := uint16(0x6000 + i)
			clientIP := net.ParseIP("2001:db8::1")
			serverIP := net.ParseIP("2001:db8::53")
			port := "10000"
			sz := 100
			proto := "udp"

			question := &layers.DNS{
				ID: dnsID, QR: false, OpCode: layers.DNSOpCodeQuery,
				Questions: []layers.DNSQuestion{
					{Name: []byte("concurrent.v6.test"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
				},
			}
			handleDns(conntable, question, logC, "INFO",
				clientIP, port, "53", serverIP, &sz, &proto, time.Now(), nil)

			answer := &layers.DNS{
				ID: dnsID, QR: true, OpCode: layers.DNSOpCodeQuery,
				Questions: []layers.DNSQuestion{
					{Name: []byte("concurrent.v6.test"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
				},
				Answers: []layers.DNSResourceRecord{
					{Type: layers.DNSTypeAAAA, IP: net.ParseIP("2001:db8::99"), TTL: 60},
				},
			}
			handleDns(conntable, answer, logC, "INFO",
				serverIP, "53", port, clientIP, &sz, &proto, time.Now(), nil)
		}
		close(done)
	}()

	<-done
	logs := ToSlice(logC)
	if len(logs) != numQueries {
		t.Fatalf("Expected %d log entries, got %d", numQueries, len(logs))
	}
}

// --- IPv6 packet layer detection edge cases ---

func TestIPv6HasIPLayerIncludesBoth(t *testing.T) {
	// Build an IPv6 packet and verify HasIPLayer returns true
	src := net.ParseIP("::1")
	dst := net.ParseIP("::1")
	dnsQ := &layers.DNS{
		ID: 1, QR: false, OpCode: layers.DNSOpCodeQuery, QDCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte("test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	raw := buildIPv6UDPDNSPacket(src, dst, 1234, 53, dnsQ)
	pd := NewPacketData(parseTestPacket(raw))
	pd.Parse()

	if !pd.HasIPLayer() {
		t.Fatal("HasIPLayer() should return true for IPv6")
	}
	if pd.HasIPv4Layer() {
		t.Fatal("HasIPv4Layer() should return false for IPv6 packet")
	}
	if !pd.HasIPv6Layer() {
		t.Fatal("HasIPv6Layer() should return true for IPv6 packet")
	}
}

// --- IPv6-specific DNS type tests ---

func TestTypeStringIPv6RelatedTypes(t *testing.T) {
	tests := []struct {
		input    layers.DNSType
		expected string
	}{
		{layers.DNSTypeAAAA, "AAAA"},
		{layers.DNSTypeRRSIG, "RRSIG"},
		{layers.DNSTypeDNSKEY, "DNSKEY"},
		{layers.DNSTypeSVCB, "SVCB"},
		{layers.DNSTypeHTTPS, "HTTPS"},
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

func TestRrStringIPv6Address(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"global unicast", "2001:db8::1"},
		{"loopback", "::1"},
		{"link-local", "fe80::1"},
		{"full form", "2001:0db8:0000:0000:0000:0000:0000:0001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			rr := layers.DNSResourceRecord{Type: layers.DNSTypeAAAA, IP: ip}
			got := RrString(rr)
			expected := ip.String() // canonical form
			if got != expected {
				t.Fatalf("RrString(AAAA %s) = %s, want %s", tt.ip, got, expected)
			}
		})
	}
}

// --- IPv6 reverse DNS (PTR for ip6.arpa) ---

func TestHandleDnsIPv6PTR(t *testing.T) {
	conntable := &connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	logC := make(chan dnsLogEntry, 10)

	clientIP := net.ParseIP("2001:db8::1")
	serverIP := net.ParseIP("2001:db8::53")

	ptrName := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	question := &layers.DNS{
		ID: 0xBBBB, QR: false, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{Name: []byte(ptrName), Type: layers.DNSTypePTR, Class: layers.DNSClassIN},
		},
	}
	sz := 150
	proto := "udp"
	handleDns(conntable, question, logC, "INFO",
		clientIP, "55555", "53", serverIP, &sz, &proto, time.Now(), nil)

	answer := &layers.DNS{
		ID: 0xBBBB, QR: true, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{Name: []byte(ptrName), Type: layers.DNSTypePTR, Class: layers.DNSClassIN},
		},
		Answers: []layers.DNSResourceRecord{
			{Type: layers.DNSTypePTR, PTR: []byte("host.example.com"), TTL: 3600},
		},
	}
	handleDns(conntable, answer, logC, "INFO",
		serverIP, "53", "55555", clientIP, &sz, &proto, time.Now(), nil)

	select {
	case entry := <-logC:
		if entry.Question != ptrName {
			t.Fatalf("Question = %s, want %s", entry.Question, ptrName)
		}
		if entry.Question_Type != "PTR" {
			t.Fatalf("Question_Type = %s, want PTR", entry.Question_Type)
		}
		if entry.Answer != "host.example.com" {
			t.Fatalf("Answer = %s, want host.example.com", entry.Answer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("No log entry received for IPv6 PTR query")
	}
}

// --- IPv6 JSON encoding test ---

func TestIPv6LogEntryEncode(t *testing.T) {
	entry := dnsLogEntry{
		Query_ID:      0x1234,
		Response_Code: 0,
		Question:      "v6.example.com",
		Question_Type: "AAAA",
		Answer:        "2001:db8::1",
		Answer_Type:   "AAAA",
		TTL:           300,
		Server:        net.ParseIP("2001:4860:4860::8888"),
		Client:        net.ParseIP("2001:db8::100"),
		Timestamp:     time.Now().UTC().String(),
		Elapsed:       1000000,
		Client_Port:   "12345",
		Level:         "INFO",
		Length:        200,
		Proto:         "udp",
	}

	encoded, err := entry.Encode()
	if err != nil {
		t.Fatalf("Encode() failed: %s", err)
	}
	if len(encoded) == 0 {
		t.Fatal("Encode() returned empty bytes")
	}

	s := string(encoded)
	if !contains(s, "2001:db8::1") {
		t.Fatalf("Encoded JSON missing IPv6 answer address")
	}
	if !contains(s, "2001:4860:4860::8888") {
		t.Fatalf("Encoded JSON missing IPv6 server address")
	}
	if !contains(s, "2001:db8::100") {
		t.Fatalf("Encoded JSON missing IPv6 client address")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- IPv6 with foundLayerType utility ---

func TestFoundLayerTypeIPv6(t *testing.T) {
	found := []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv6, layers.LayerTypeDNS}

	if !foundLayerType(layers.LayerTypeIPv6, found) {
		t.Fatal("expected to find IPv6")
	}
	if foundLayerType(layers.LayerTypeIPv4, found) {
		t.Fatal("did not expect to find IPv4")
	}
	if !foundLayerType(layers.LayerTypeDNS, found) {
		t.Fatal("expected to find DNS")
	}
}

// --- initLogEntry with IPv6 addresses ---

func TestInitLogEntryIPv6Addresses(t *testing.T) {
	srcIP := net.ParseIP("2001:4860:4860::8888")
	dstIP := net.ParseIP("2001:db8::1")

	question := layers.DNS{
		Questions: []layers.DNSQuestion{
			{Name: []byte("v6test.example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		},
	}
	reply := layers.DNS{
		ResponseCode: 0,
		ID:           0x4444,
		Answers: []layers.DNSResourceRecord{
			{Type: layers.DNSTypeAAAA, IP: net.ParseIP("2001:db8::42"), TTL: 120},
		},
	}
	sz := 150
	proto := "udp"
	logs := []dnsLogEntry{}

	initLogEntry("INFO", srcIP, "53", dstIP, &sz, &proto, question, reply, time.Now(), &logs)

	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if !logs[0].Server.Equal(srcIP) {
		t.Fatalf("Server = %s, want %s", logs[0].Server, srcIP)
	}
	if !logs[0].Client.Equal(dstIP) {
		t.Fatalf("Client = %s, want %s", logs[0].Client, dstIP)
	}
	if logs[0].Answer != "2001:db8::42" {
		t.Fatalf("Answer = %s, want 2001:db8::42", logs[0].Answer)
	}
}
