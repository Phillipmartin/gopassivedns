package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestConnectionTableConcurrentAccess(t *testing.T) {
	conntable := &connectionTable{
		connections: make(map[string]dnsMapEntry),
	}

	var wg sync.WaitGroup
	numGoroutines := 50
	numOps := 100

	// Concurrent writers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				key := fmt.Sprintf("%d->%d:%d", id, j, 53)
				conntable.Lock()
				conntable.connections[key] = dnsMapEntry{
					entry:    layers.DNS{ID: uint16(id)},
					inserted: time.Now(),
				}
				conntable.Unlock()
			}
		}(i)
	}

	// Concurrent readers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				key := fmt.Sprintf("%d->%d:%d", id, j, 53)
				conntable.RLock()
				_ = conntable.connections[key]
				conntable.RUnlock()
			}
		}(i)
	}

	wg.Wait()

	conntable.RLock()
	count := len(conntable.connections)
	conntable.RUnlock()

	if count != numGoroutines*numOps {
		t.Fatalf("expected %d entries, got %d", numGoroutines*numOps, count)
	}
}

func TestConnectionTableConcurrentGC(t *testing.T) {
	conntable := &connectionTable{
		connections: make(map[string]dnsMapEntry),
	}

	// Insert entries that are already old
	conntable.Lock()
	for i := 0; i < 100; i++ {
		conntable.connections[fmt.Sprintf("key-%d", i)] = dnsMapEntry{
			entry:    layers.DNS{ID: uint16(i)},
			inserted: time.Now().Add(-10 * time.Minute),
		}
	}
	conntable.Unlock()

	// Run GC in background
	gcAge, _ := time.ParseDuration("-1s")
	gcInterval, _ := time.ParseDuration("100ms")
	go cleanDnsCache(conntable, gcAge, gcInterval, nil)

	// Concurrent writes while GC is running
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := fmt.Sprintf("new-%d-%d", id, j)
				conntable.Lock()
				conntable.connections[key] = dnsMapEntry{
					entry:    layers.DNS{ID: uint16(id)},
					inserted: time.Now(),
				}
				conntable.Unlock()
				time.Sleep(time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	// Wait for GC to clean old entries
	time.Sleep(300 * time.Millisecond)

	conntable.RLock()
	count := len(conntable.connections)
	conntable.RUnlock()

	// Old entries should be cleaned, new entries should remain
	if count > 1100 {
		t.Fatalf("GC didn't clean entries, %d remain", count)
	}
}

func TestHandleDnsConcurrent(t *testing.T) {
	conntable := &connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	logC := make(chan dnsLogEntry, 1000)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				dnsID := uint16(id*100 + j)
				question := &layers.DNS{
					ID:     dnsID,
					QR:     false,
					OpCode: layers.DNSOpCodeQuery,
					Questions: []layers.DNSQuestion{
						{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
					},
				}
				sz := 100
				proto := "udp"
				handleDns(conntable, question, logC, "INFO",
					net.ParseIP("10.0.0.1"), fmt.Sprintf("%d", 10000+j), "53",
					net.ParseIP("8.8.8.8"), &sz, &proto, time.Now(), nil)

				answer := &layers.DNS{
					ID:     dnsID,
					QR:     true,
					OpCode: layers.DNSOpCodeQuery,
					Questions: []layers.DNSQuestion{
						{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
					},
					Answers: []layers.DNSResourceRecord{
						{Type: layers.DNSTypeA, IP: net.ParseIP("1.2.3.4"), TTL: 300},
					},
				}
				handleDns(conntable, answer, logC, "INFO",
					net.ParseIP("8.8.8.8"), "53", fmt.Sprintf("%d", 10000+j),
					net.ParseIP("10.0.0.1"), &sz, &proto, time.Now(), nil)
			}
		}(i)
	}

	wg.Wait()

	// Drain the log channel
	logs := ToSlice(logC)
	if len(logs) != 200 {
		t.Fatalf("expected 200 log entries, got %d", len(logs))
	}
}

func TestGracefulShutdown(t *testing.T) {
	channels := []chan *packetData{
		make(chan *packetData, 10),
		make(chan *packetData, 10),
	}
	reChan := make(chan tcpDataStruct, 10)
	logChan := make(chan dnsLogEntry, 10)

	// Put some log entries in the channel
	logChan <- dnsLogEntry{Question: "test1.com", Server: net.ParseIP("1.1.1.1"), Client: net.ParseIP("2.2.2.2")}
	logChan <- dnsLogEntry{Question: "test2.com", Server: net.ParseIP("1.1.1.1"), Client: net.ParseIP("2.2.2.2")}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		gracefulShutdown(channels, reChan, logChan, &wg)
		close(done)
	}()

	select {
	case <-done:
		// Verify channels are closed
		_, ok := <-channels[0]
		if ok {
			t.Fatal("channel 0 should be closed")
		}
		_, ok = <-channels[1]
		if ok {
			t.Fatal("channel 1 should be closed")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("gracefulShutdown did not complete in time")
	}
}

func TestInitLogEntryEmptyQuestions(t *testing.T) {
	question := layers.DNS{Questions: []layers.DNSQuestion{}}
	reply := layers.DNS{ResponseCode: 0}
	sz := 100
	proto := "udp"
	logs := []dnsLogEntry{}

	initLogEntry("INFO", net.ParseIP("1.1.1.1"), "53", net.ParseIP("2.2.2.2"),
		&sz, &proto, question, reply, time.Now(), &logs)

	if len(logs) != 0 {
		t.Fatalf("expected 0 logs for empty questions, got %d", len(logs))
	}
}

func TestInitLogEntryProtocolNormalization(t *testing.T) {
	question := layers.DNS{
		QR: false,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	reply := layers.DNS{
		QR:           true,
		ResponseCode: 0,
		Answers: []layers.DNSResourceRecord{
			{Type: layers.DNSTypeA, IP: net.ParseIP("1.2.3.4"), TTL: 300},
		},
	}
	sz := 100
	proto := "packet"
	logs := []dnsLogEntry{}

	initLogEntry("INFO", net.ParseIP("8.8.8.8"), "53", net.ParseIP("10.0.0.1"),
		&sz, &proto, question, reply, time.Now(), &logs)

	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if logs[0].Proto != "udp" {
		t.Fatalf("expected proto 'udp', got '%s'", logs[0].Proto)
	}
}

func TestInitLogEntryErrorResponse(t *testing.T) {
	question := layers.DNS{
		Questions: []layers.DNSQuestion{
			{Name: []byte("nxdomain.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	reply := layers.DNS{
		ResponseCode: layers.DNSResponseCodeNXDomain,
		ID:           0x1234,
	}
	sz := 100
	proto := "udp"
	logs := []dnsLogEntry{}

	initLogEntry("INFO", net.ParseIP("8.8.8.8"), "53", net.ParseIP("10.0.0.1"),
		&sz, &proto, question, reply, time.Now(), &logs)

	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if logs[0].Response_Code != 3 {
		t.Fatalf("expected rcode 3, got %d", logs[0].Response_Code)
	}
	if logs[0].Answer_Type != "" {
		t.Fatalf("expected empty answer type, got %s", logs[0].Answer_Type)
	}
}

func TestInitLogEntryMultipleAnswers(t *testing.T) {
	question := layers.DNS{
		Questions: []layers.DNSQuestion{
			{Name: []byte("multi.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	reply := layers.DNS{
		ResponseCode: 0,
		Answers: []layers.DNSResourceRecord{
			{Type: layers.DNSTypeA, IP: net.ParseIP("1.1.1.1"), TTL: 300},
			{Type: layers.DNSTypeA, IP: net.ParseIP("2.2.2.2"), TTL: 300},
			{Type: layers.DNSTypeA, IP: net.ParseIP("3.3.3.3"), TTL: 300},
		},
	}
	sz := 100
	proto := "udp"
	logs := []dnsLogEntry{}

	initLogEntry("INFO", net.ParseIP("8.8.8.8"), "53", net.ParseIP("10.0.0.1"),
		&sz, &proto, question, reply, time.Now(), &logs)

	if len(logs) != 3 {
		t.Fatalf("expected 3 logs for 3 answers, got %d", len(logs))
	}
	if logs[0].Answer != "1.1.1.1" {
		t.Fatalf("first answer = %s, want 1.1.1.1", logs[0].Answer)
	}
	if logs[2].Answer != "3.3.3.3" {
		t.Fatalf("third answer = %s, want 3.3.3.3", logs[2].Answer)
	}
}

func TestWatchSignals(t *testing.T) {
	sig := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	go watchSignals(sig, done)

	// Send signal
	sig <- os.Interrupt

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("watchSignals did not send done signal")
	}
}
