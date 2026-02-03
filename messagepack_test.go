package main

import (
	"net"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestMarshalMsgpack(t *testing.T) {
	entry := dnsLogEntry{
		Query_ID:             1234,
		Response_Code:        0,
		Question:             "example.com",
		Question_Type:        "A",
		Answer:               "1.2.3.4",
		Answer_Type:          "A",
		TTL:                  300,
		Server:               net.ParseIP("8.8.8.8"),
		Client:               net.ParseIP("10.0.0.1"),
		Timestamp:            "2024-01-01T00:00:00Z",
		Elapsed:              1000,
		Client_Port:          "12345",
		Level:                "INFO",
		Length:               100,
		Proto:                "udp",
		Truncated:            false,
		Authoritative_Answer: true,
		Recursion_Desired:    true,
		Recursion_Available:  true,
	}

	data, err := entry.MarshalMsgpack()
	if err != nil {
		t.Fatalf("MarshalMsgpack failed: %s", err)
	}
	if len(data) == 0 {
		t.Fatal("MarshalMsgpack returned empty data")
	}

	// Unmarshal into logEntry to verify fields
	var le logEntry
	err = msgpack.Unmarshal(data, &le)
	if err != nil {
		t.Fatalf("Failed to unmarshal msgpack: %s", err)
	}

	if le.Query_ID != 1234 {
		t.Fatalf("Query_ID = %d, want 1234", le.Query_ID)
	}
	if le.Question != "example.com" {
		t.Fatalf("Question = %s, want example.com", le.Question)
	}
	if le.Answer != "1.2.3.4" {
		t.Fatalf("Answer = %s, want 1.2.3.4", le.Answer)
	}
	if le.Server != "8.8.8.8" {
		t.Fatalf("Server = %s, want 8.8.8.8", le.Server)
	}
	if le.Client != "10.0.0.1" {
		t.Fatalf("Client = %s, want 10.0.0.1", le.Client)
	}
	if le.TTL != 300 {
		t.Fatalf("TTL = %d, want 300", le.TTL)
	}
	if le.Proto != "udp" {
		t.Fatalf("Proto = %s, want udp", le.Proto)
	}
	if !le.Authoritative_Answer {
		t.Fatal("Authoritative_Answer should be true")
	}
	if !le.Recursion_Desired {
		t.Fatal("Recursion_Desired should be true")
	}
	if le.Truncated {
		t.Fatal("Truncated should be false")
	}
	if le.Level != "INFO" {
		t.Fatalf("Level = %s, want INFO", le.Level)
	}
}

func TestMarshalMsgpackEmptyLevel(t *testing.T) {
	entry := dnsLogEntry{
		Question: "example.com",
		Server:   net.ParseIP("8.8.8.8"),
		Client:   net.ParseIP("10.0.0.1"),
		Level:    "",
	}

	data, err := entry.MarshalMsgpack()
	if err != nil {
		t.Fatalf("MarshalMsgpack failed: %s", err)
	}

	var le logEntry
	err = msgpack.Unmarshal(data, &le)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %s", err)
	}

	if le.Level != "" {
		t.Fatalf("Level should be empty, got %s", le.Level)
	}
}
