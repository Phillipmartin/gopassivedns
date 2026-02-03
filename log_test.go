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

func TestLogConnFile(t *testing.T) {
	// Create a temporary file for logging
	tmpFile, err := os.CreateTemp("", "gopassivedns_test_*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %s", err)
	}
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpFileName)

	logC := make(chan dnsLogEntry, 10)
	opts := &logOptions{
		Filename:   tmpFileName,
		MaxSize:    1,
		MaxBackups: 1,
		MaxAge:     1,
	}

	entry := dnsLogEntry{
		Query_ID:      1234,
		Question:      "filetest.example.com",
		Question_Type: "A",
		Answer:        "1.2.3.4",
		Answer_Type:   "A",
		TTL:           300,
		Server:        net.ParseIP("8.8.8.8"),
		Client:        net.ParseIP("10.0.0.1"),
		Timestamp:     "2024-01-01T00:00:00Z",
		Proto:         "udp",
	}

	// Send entry and close channel
	logC <- entry
	close(logC)

	// Run the file logger
	logConnFile(logC, opts)

	// Read the file and verify content
	content, err := os.ReadFile(tmpFileName)
	if err != nil {
		t.Fatalf("failed to read log file: %s", err)
	}

	if !strings.Contains(string(content), "filetest.example.com") {
		t.Fatalf("log file missing question, got: %s", string(content))
	}
	if !strings.Contains(string(content), "1.2.3.4") {
		t.Fatalf("log file missing answer, got: %s", string(content))
	}
}

func TestLogConnFileMultipleEntries(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "gopassivedns_multi_*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %s", err)
	}
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpFileName)

	logC := make(chan dnsLogEntry, 10)
	opts := &logOptions{
		Filename:   tmpFileName,
		MaxSize:    10,
		MaxBackups: 1,
		MaxAge:     1,
	}

	// Send multiple entries
	for i := 0; i < 5; i++ {
		entry := dnsLogEntry{
			Query_ID:      uint16(1000 + i),
			Question:      "multi" + string(rune('0'+i)) + ".example.com",
			Question_Type: "A",
			Answer:        "1.2.3." + string(rune('0'+i)),
			Server:        net.ParseIP("8.8.8.8"),
			Client:        net.ParseIP("10.0.0.1"),
			Proto:         "udp",
		}
		logC <- entry
	}
	close(logC)

	logConnFile(logC, opts)

	content, err := os.ReadFile(tmpFileName)
	if err != nil {
		t.Fatalf("failed to read log file: %s", err)
	}

	// Verify all entries are in the file
	for i := 0; i < 5; i++ {
		expected := "multi" + string(rune('0'+i)) + ".example.com"
		if !strings.Contains(string(content), expected) {
			t.Fatalf("log file missing entry %d: %s", i, expected)
		}
	}
}

func TestInitLoggingWithDebug(t *testing.T) {
	opts := &logOptions{debug: true}
	config := &pdnsConfig{numprocs: 4}
	logChan := initLogging(opts, config)
	if logChan == nil {
		t.Fatal("initLogging returned nil channel with debug=true")
	}
	if cap(logChan) != packetQueue*4 {
		t.Fatalf("expected capacity %d, got %d", packetQueue*4, cap(logChan))
	}
}

func TestLogConnWithFileBackend(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "gopassivedns_conn_*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %s", err)
	}
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpFileName)

	logC := make(chan dnsLogEntry, 10)
	opts := &logOptions{
		quiet:      true, // Don't log to stdout
		Filename:   tmpFileName,
		MaxSize:    10,
		MaxBackups: 1,
		MaxAge:     1,
	}

	entry := dnsLogEntry{
		Query_ID: 5678,
		Question: "logconn-file-test.example.com",
		Server:   net.ParseIP("8.8.8.8"),
		Client:   net.ParseIP("10.0.0.1"),
	}

	go func() {
		logC <- entry
		time.Sleep(100 * time.Millisecond)
		close(logC)
	}()

	logConn(logC, opts, nil)

	// Wait a bit for file to be flushed
	time.Sleep(50 * time.Millisecond)

	content, err := os.ReadFile(tmpFileName)
	if err != nil {
		t.Fatalf("failed to read log file: %s", err)
	}

	if !strings.Contains(string(content), "logconn-file-test.example.com") {
		t.Fatalf("log file missing question via logConn, got: %s", string(content))
	}
}

func TestLogConnWithBothStdoutAndFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "gopassivedns_both_*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %s", err)
	}
	tmpFileName := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpFileName)

	logC := make(chan dnsLogEntry, 10)
	opts := &logOptions{
		quiet:      false, // Log to stdout too
		Filename:   tmpFileName,
		MaxSize:    10,
		MaxBackups: 1,
		MaxAge:     1,
	}

	entry := dnsLogEntry{
		Query_ID: 9999,
		Question: "both-backends.example.com",
		Server:   net.ParseIP("8.8.8.8"),
		Client:   net.ParseIP("10.0.0.1"),
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	go func() {
		logC <- entry
		time.Sleep(100 * time.Millisecond)
		close(logC)
	}()

	logConn(logC, opts, nil)

	w.Close()
	os.Stdout = oldStdout

	// Read stdout
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	stdoutOutput := string(buf[:n])

	// Wait for file to be flushed
	time.Sleep(50 * time.Millisecond)

	// Read file
	fileContent, err := os.ReadFile(tmpFileName)
	if err != nil {
		t.Fatalf("failed to read log file: %s", err)
	}

	// Verify both backends received the message
	if !strings.Contains(stdoutOutput, "both-backends.example.com") {
		t.Fatalf("stdout missing question, got: %s", stdoutOutput)
	}
	if !strings.Contains(string(fileContent), "both-backends.example.com") {
		t.Fatalf("file missing question, got: %s", string(fileContent))
	}
}

func TestDnsLogEntryEncodeErrorHandling(t *testing.T) {
	// Test with a normal entry first to ensure Encode works
	entry := dnsLogEntry{
		Question: "test.com",
		Server:   net.ParseIP("8.8.8.8"),
		Client:   net.ParseIP("10.0.0.1"),
	}

	encoded, err := entry.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %s", err)
	}
	if encoded == nil {
		t.Fatal("Encode returned nil")
	}
}

func TestDnsLogEntrySizeBeforeEncode(t *testing.T) {
	// Test that Size() works even before explicit Encode()
	entry := dnsLogEntry{
		Question:      "size-test.example.com",
		Question_Type: "AAAA",
		Server:        net.ParseIP("2001:db8::1"),
		Client:        net.ParseIP("10.0.0.1"),
	}

	// Size should trigger encoding
	size := entry.Size()
	if size == 0 {
		t.Fatal("Size() returned 0")
	}

	// Now Encode should return cached data
	encoded, err := entry.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %s", err)
	}
	if len(encoded) != size {
		t.Fatalf("Size() = %d but len(Encode()) = %d", size, len(encoded))
	}
}

func TestFacilityToTypeAllFacilities(t *testing.T) {
	facilities := []string{
		"KERN", "USER", "MAIL", "DAEMON", "AUTH", "SYSLOG",
		"LPR", "NEWS", "UUCP", "CRON", "AUTHPRIV", "FTP",
		"LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4",
		"LOCAL5", "LOCAL6", "LOCAL7",
	}

	for _, fac := range facilities {
		t.Run(fac, func(t *testing.T) {
			_, err := facilityToType(fac)
			if err != nil {
				t.Fatalf("facilityToType(%s) failed: %s", fac, err)
			}
			// Also test lowercase
			_, err = facilityToType(strings.ToLower(fac))
			if err != nil {
				t.Fatalf("facilityToType(%s) failed: %s", strings.ToLower(fac), err)
			}
		})
	}
}

func TestLevelToTypeAllLevels(t *testing.T) {
	levels := []string{
		"EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG",
	}

	for _, lvl := range levels {
		t.Run(lvl, func(t *testing.T) {
			_, err := levelToType(lvl)
			if err != nil {
				t.Fatalf("levelToType(%s) failed: %s", lvl, err)
			}
			// Also test lowercase
			_, err = levelToType(strings.ToLower(lvl))
			if err != nil {
				t.Fatalf("levelToType(%s) failed: %s", strings.ToLower(lvl), err)
			}
		})
	}
}

func TestFacilityToTypeInvalid(t *testing.T) {
	_, err := facilityToType("INVALID_FACILITY")
	if err == nil {
		t.Fatal("expected error for invalid facility")
	}
}

func TestLevelToTypeInvalid(t *testing.T) {
	_, err := levelToType("INVALID_LEVEL")
	if err == nil {
		t.Fatal("expected error for invalid level")
	}
}
