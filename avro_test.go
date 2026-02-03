package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestCRC64AvroKnownValue(t *testing.T) {
	// The CRC-64-AVRO of an empty byte slice should equal the EMPTY constant.
	fp := fingerprintCRC64Avro([]byte{})
	if fp != crc64AvroEmpty {
		t.Errorf("CRC64-AVRO of empty input: got %x, want %x", fp, crc64AvroEmpty)
	}

	// "0" should produce a known non-empty fingerprint (sanity check)
	fp2 := fingerprintCRC64Avro([]byte("0"))
	if fp2 == crc64AvroEmpty {
		t.Error("CRC64-AVRO of '0' should not equal EMPTY")
	}
}

func TestAvroSingleObjectHeader(t *testing.T) {
	entry := dnsLogEntry{
		Query_ID:      1234,
		Response_Code: 0,
		Question:      "example.com",
		Question_Type: "A",
		Answer:        "1.2.3.4",
		Answer_Type:   "A",
		TTL:           300,
		Server:        net.ParseIP("8.8.8.8"),
		Client:        net.ParseIP("10.0.0.1"),
		Timestamp:     "2024-01-01T00:00:00Z",
		Elapsed:       1000,
		Client_Port:   "12345",
		Level:         "INFO",
		Length:        64,
		Proto:         "udp",
	}

	encoded, err := entry.EncodeAvroSingleObject()
	if err != nil {
		t.Fatalf("EncodeAvroSingleObject failed: %v", err)
	}

	// Check marker bytes
	if encoded[0] != 0xC3 || encoded[1] != 0x01 {
		t.Errorf("Wrong marker: got %x %x, want C3 01", encoded[0], encoded[1])
	}

	// Check fingerprint is 8 bytes (non-zero)
	fp := binary.LittleEndian.Uint64(encoded[2:10])
	if fp == 0 {
		t.Error("Fingerprint should not be zero")
	}

	// Payload should follow
	if len(encoded) <= 10 {
		t.Error("Encoded message should have payload after header")
	}
}

func TestAvroZigzagEncoding(t *testing.T) {
	tests := []struct {
		input    int64
		expected []byte
	}{
		{0, []byte{0}},
		{-1, []byte{1}},
		{1, []byte{2}},
		{-2, []byte{3}},
		{2, []byte{4}},
		{-64, []byte{127}},
		{64, []byte{128, 1}},
	}

	for _, tc := range tests {
		result := appendAvroLong(nil, tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("zigzag(%d): got %v, want %v", tc.input, result, tc.expected)
			continue
		}
		for i := range result {
			if result[i] != tc.expected[i] {
				t.Errorf("zigzag(%d): byte %d got %x, want %x", tc.input, i, result[i], tc.expected[i])
			}
		}
	}
}

func TestAvroSchemaFingerprint(t *testing.T) {
	// Verify the precomputed fingerprint matches a fresh computation
	fp := fingerprintCRC64Avro([]byte(dnsLogEntryAvroSchema))
	expected := binary.LittleEndian.Uint64(avroSchemaFingerprint[:])
	if fp != expected {
		t.Errorf("Schema fingerprint mismatch: got %x, want %x", fp, expected)
	}
}
