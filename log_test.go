package main

import (
	"bytes"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLogOptionsAccessors(t *testing.T) {
	t.Run("IsDebug", func(t *testing.T) {
		lo := &logOptions{debug: true}
		if !lo.IsDebug() {
			t.Fatal("expected IsDebug() == true")
		}
		lo.debug = false
		if lo.IsDebug() {
			t.Fatal("expected IsDebug() == false")
		}
	})

	t.Run("LogToStdout", func(t *testing.T) {
		lo := &logOptions{quiet: false}
		if !lo.LogToStdout() {
			t.Fatal("expected LogToStdout() == true when quiet=false")
		}
		lo.quiet = true
		if lo.LogToStdout() {
			t.Fatal("expected LogToStdout() == false when quiet=true")
		}
	})

	t.Run("LogToFile", func(t *testing.T) {
		lo := &logOptions{Filename: ""}
		if lo.LogToFile() {
			t.Fatal("expected LogToFile() == false when Filename is empty")
		}
		lo.Filename = "/tmp/test.log"
		if !lo.LogToFile() {
			t.Fatal("expected LogToFile() == true")
		}
	})

	t.Run("LogToKafka", func(t *testing.T) {
		lo := &logOptions{KafkaBrokers: "", KafkaTopic: ""}
		if lo.LogToKafka() {
			t.Fatal("expected LogToKafka() == false when both empty")
		}
		lo.KafkaBrokers = "localhost:9092"
		if !lo.LogToKafka() {
			t.Fatal("expected LogToKafka() == true when brokers set")
		}
		lo.KafkaBrokers = ""
		lo.KafkaTopic = "dns"
		if !lo.LogToKafka() {
			t.Fatal("expected LogToKafka() == true when topic set")
		}
	})

	t.Run("LogToSyslog", func(t *testing.T) {
		lo := &logOptions{SyslogFacility: "", SyslogPriority: ""}
		if lo.LogToSyslog() {
			t.Fatal("expected LogToSyslog() == false")
		}
		lo.SyslogFacility = "LOCAL0"
		if lo.LogToSyslog() {
			t.Fatal("expected LogToSyslog() == false when priority empty")
		}
		lo.SyslogPriority = "INFO"
		if !lo.LogToSyslog() {
			t.Fatal("expected LogToSyslog() == true")
		}
	})

	t.Run("LogToFluentd", func(t *testing.T) {
		lo := &logOptions{FluentdSocket: ""}
		if lo.LogToFluentd() {
			t.Fatal("expected LogToFluentd() == false")
		}
		lo.FluentdSocket = "/tmp/fluent.sock"
		if !lo.LogToFluentd() {
			t.Fatal("expected LogToFluentd() == true")
		}
	})
}

func TestNewLogOptions(t *testing.T) {
	config := &pdnsConfig{
		quiet:          true,
		debug:          true,
		logFile:        "/tmp/test.log",
		fluentdSocket:  "/tmp/fluent.sock",
		kafkaBrokers:   "localhost:9092",
		kafkaTopic:     "dns",
		logMaxAge:      7,
		logMaxSize:     50,
		logMaxBackups:  2,
		syslogFacility: "LOCAL0",
		syslogPriority: "INFO",
		sensorName:     "test-sensor",
	}

	opts := NewLogOptions(config)

	if !opts.quiet {
		t.Fatal("quiet should be true")
	}
	if !opts.debug {
		t.Fatal("debug should be true")
	}
	if opts.Filename != "/tmp/test.log" {
		t.Fatalf("Filename = %s", opts.Filename)
	}
	if opts.FluentdSocket != "/tmp/fluent.sock" {
		t.Fatalf("FluentdSocket = %s", opts.FluentdSocket)
	}
	if opts.KafkaBrokers != "localhost:9092" {
		t.Fatalf("KafkaBrokers = %s", opts.KafkaBrokers)
	}
	if opts.KafkaTopic != "dns" {
		t.Fatalf("KafkaTopic = %s", opts.KafkaTopic)
	}
	if opts.MaxAge != 7 {
		t.Fatalf("MaxAge = %d", opts.MaxAge)
	}
	if opts.MaxSize != 50 {
		t.Fatalf("MaxSize = %d", opts.MaxSize)
	}
	if opts.MaxBackups != 2 {
		t.Fatalf("MaxBackups = %d", opts.MaxBackups)
	}
	if opts.SyslogFacility != "LOCAL0" {
		t.Fatalf("SyslogFacility = %s", opts.SyslogFacility)
	}
	if opts.SyslogPriority != "INFO" {
		t.Fatalf("SyslogPriority = %s", opts.SyslogPriority)
	}
	if opts.SensorName != "test-sensor" {
		t.Fatalf("SensorName = %s", opts.SensorName)
	}
}

func TestInitLogging(t *testing.T) {
	opts := &logOptions{debug: false}
	config := &pdnsConfig{numprocs: 2}
	logChan := initLogging(opts, config)
	if logChan == nil {
		t.Fatal("initLogging returned nil channel")
	}
	if cap(logChan) != packetQueue*2 {
		t.Fatalf("expected capacity %d, got %d", packetQueue*2, cap(logChan))
	}
}

func TestDnsLogEntryEncode(t *testing.T) {
	entry := dnsLogEntry{
		Query_ID:      1234,
		Question:      "example.com",
		Question_Type: "A",
		Answer:        "1.2.3.4",
		Answer_Type:   "A",
		Server:        net.ParseIP("8.8.8.8"),
		Client:        net.ParseIP("10.0.0.1"),
		Timestamp:     "2024-01-01T00:00:00Z",
		Proto:         "udp",
	}

	encoded, err := entry.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %s", err)
	}
	if len(encoded) == 0 {
		t.Fatal("Encode returned empty")
	}

	// Verify idempotency
	encoded2, err2 := entry.Encode()
	if err2 != nil {
		t.Fatal("second Encode failed")
	}
	if !bytes.Equal(encoded, encoded2) {
		t.Fatal("Encode not idempotent")
	}
}

func TestDnsLogEntrySize(t *testing.T) {
	entry := dnsLogEntry{
		Question: "example.com",
		Server:   net.ParseIP("8.8.8.8"),
		Client:   net.ParseIP("10.0.0.1"),
	}
	sz := entry.Size()
	if sz == 0 {
		t.Fatal("Size() returned 0")
	}
	encoded, _ := entry.Encode()
	if sz != len(encoded) {
		t.Fatalf("Size() = %d, len(Encode()) = %d", sz, len(encoded))
	}
}

func TestLogConnStdout(t *testing.T) {
	logC := make(chan dnsLogEntry, 1)

	entry := dnsLogEntry{
		Question: "test.com",
		Server:   net.ParseIP("8.8.8.8"),
		Client:   net.ParseIP("10.0.0.1"),
	}

	logC <- entry
	close(logC)

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logConnStdout(logC)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "test.com") {
		t.Fatalf("stdout output missing question, got: %s", output)
	}
}

func TestLogConnKafka(t *testing.T) {
	// Skip: this is an integration test that requires a real Kafka broker
	// The test was designed for a stub that no longer exists
	t.Skip("Skipping Kafka integration test - requires external Kafka broker")

	logC := make(chan dnsLogEntry, 1)

	entry := dnsLogEntry{
		Question: "kafka-test.com",
		Server:   net.ParseIP("8.8.8.8"),
		Client:   net.ParseIP("10.0.0.1"),
	}

	logC <- entry
	close(logC)

	// Capture stdout (kafka stub prints to stdout)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logConnKafka(logC, &logOptions{})

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "kafka-test.com") {
		t.Fatalf("kafka output missing question, got: %s", output)
	}
	if !strings.Contains(output, "Kafka:") {
		t.Fatalf("kafka output missing prefix, got: %s", output)
	}
}

func TestLogConnDispatch(t *testing.T) {
	// Test logConn dispatching to stdout only (quiet=false, no other backends)
	logC := make(chan dnsLogEntry, 10)
	opts := &logOptions{quiet: false}

	entry := dnsLogEntry{
		Question: "dispatch-test.com",
		Server:   net.ParseIP("8.8.8.8"),
		Client:   net.ParseIP("10.0.0.1"),
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	go func() {
		logC <- entry
		// Give logConn time to dispatch before closing
		time.Sleep(100 * time.Millisecond)
		close(logC)
	}()

	logConn(logC, opts, nil)

	w.Close()
	os.Stdout = old

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "dispatch-test.com") {
		t.Fatalf("logConn dispatch missing data, got: %s", output)
	}
}

func TestLogConnQuiet(t *testing.T) {
	// When quiet=true and no other backends, messages should be consumed but not output
	logC := make(chan dnsLogEntry, 10)
	opts := &logOptions{quiet: true}

	entry := dnsLogEntry{
		Question: "quiet-test.com",
		Server:   net.ParseIP("8.8.8.8"),
		Client:   net.ParseIP("10.0.0.1"),
	}

	go func() {
		logC <- entry
		time.Sleep(100 * time.Millisecond)
		close(logC)
	}()

	// This should complete without hanging even with no backends
	logConn(logC, opts, nil)
}

func TestFacilityToTypeCase(t *testing.T) {
	// Test case insensitivity
	fac, err := facilityToType("kern")
	if err != nil {
		t.Fatalf("lowercase kern should work: %s", err)
	}
	fac2, _ := facilityToType("KERN")
	if fac != fac2 {
		t.Fatal("case insensitive matching failed")
	}
}

func TestLevelToTypeCase(t *testing.T) {
	lvl, err := levelToType("debug")
	if err != nil {
		t.Fatalf("lowercase debug should work: %s", err)
	}
	lvl2, _ := levelToType("DEBUG")
	if lvl != lvl2 {
		t.Fatal("case insensitive matching failed")
	}
}
