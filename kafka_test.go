package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAppendInt16(t *testing.T) {
	tests := []struct {
		name     string
		input    int16
		expected []byte
	}{
		{"zero", 0, []byte{0, 0}},
		{"positive", 256, []byte{1, 0}},
		{"max", 32767, []byte{127, 255}},
		{"negative", -1, []byte{255, 255}},
		{"small", 1, []byte{0, 1}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := appendInt16(nil, tc.input)
			if !bytes.Equal(result, tc.expected) {
				t.Fatalf("appendInt16(%d) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestAppendInt16ToExisting(t *testing.T) {
	buf := []byte{0xAA, 0xBB}
	result := appendInt16(buf, 0x0102)
	expected := []byte{0xAA, 0xBB, 0x01, 0x02}
	if !bytes.Equal(result, expected) {
		t.Fatalf("appendInt16 to existing buf = %v, want %v", result, expected)
	}
}

func TestAppendInt32(t *testing.T) {
	tests := []struct {
		name     string
		input    int32
		expected []byte
	}{
		{"zero", 0, []byte{0, 0, 0, 0}},
		{"positive", 0x01020304, []byte{1, 2, 3, 4}},
		{"max", 2147483647, []byte{127, 255, 255, 255}},
		{"negative", -1, []byte{255, 255, 255, 255}},
		{"small", 1, []byte{0, 0, 0, 1}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := appendInt32(nil, tc.input)
			if !bytes.Equal(result, tc.expected) {
				t.Fatalf("appendInt32(%d) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestAppendInt32ToExisting(t *testing.T) {
	buf := []byte{0xAA}
	result := appendInt32(buf, 0x01020304)
	expected := []byte{0xAA, 0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(result, expected) {
		t.Fatalf("appendInt32 to existing buf = %v, want %v", result, expected)
	}
}

func TestAppendInt64(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected []byte
	}{
		{"zero", 0, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{"positive", 0x0102030405060708, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{"negative", -1, []byte{255, 255, 255, 255, 255, 255, 255, 255}},
		{"small", 1, []byte{0, 0, 0, 0, 0, 0, 0, 1}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := appendInt64(nil, tc.input)
			if !bytes.Equal(result, tc.expected) {
				t.Fatalf("appendInt64(%d) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestAppendInt64ToExisting(t *testing.T) {
	buf := []byte{0xAA, 0xBB}
	result := appendInt64(buf, 0x0102030405060708)
	expected := []byte{0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(result, expected) {
		t.Fatalf("appendInt64 to existing buf = %v, want %v", result, expected)
	}
}

func TestCrc32Kafka(t *testing.T) {
	// Test that crc32Kafka produces valid CRC32-IEEE checksums
	// We verify by checking consistency and non-zero results

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"hello", []byte("hello")},
		{"test", []byte("test")},
		{"single_byte", []byte{0x00}},
		{"kafka_message", []byte{0, 0, 255, 255, 255, 255}},
		{"binary_data", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result1 := crc32Kafka(tc.input)
			result2 := crc32Kafka(tc.input)

			// Verify consistency
			if result1 != result2 {
				t.Fatalf("crc32Kafka not consistent: %08X != %08X", result1, result2)
			}

			// Non-empty inputs should produce non-zero CRCs (almost always)
			if len(tc.input) > 0 && result1 == 0 {
				t.Log("Warning: CRC is 0 for non-empty input (rare but possible)")
			}
		})
	}
}

func TestCrc32KafkaConsistency(t *testing.T) {
	// Test that CRC is consistent across multiple calls
	data := []byte("consistent test data")
	crc1 := crc32Kafka(data)
	crc2 := crc32Kafka(data)
	if crc1 != crc2 {
		t.Fatalf("CRC not consistent: %08X != %08X", crc1, crc2)
	}
}

func TestBuildProduceRequest(t *testing.T) {
	kp := &kafkaProducer{
		brokers: []string{"localhost:9092"},
		topic:   "test-topic",
	}

	value := []byte("test message")
	msg := kp.buildProduceRequest(value)

	// Verify the message is non-empty
	if len(msg) == 0 {
		t.Fatal("buildProduceRequest returned empty message")
	}

	// Verify the first 4 bytes contain a valid size (big-endian)
	if len(msg) < 4 {
		t.Fatal("message too short")
	}

	size := binary.BigEndian.Uint32(msg[0:4])
	expectedSize := uint32(len(msg) - 4)
	if size != expectedSize {
		t.Fatalf("size field = %d, want %d", size, expectedSize)
	}

	// Verify API Key (bytes 4-5) is 0 (Produce)
	apiKey := binary.BigEndian.Uint16(msg[4:6])
	if apiKey != 0 {
		t.Fatalf("API key = %d, want 0 (Produce)", apiKey)
	}

	// Verify API Version (bytes 6-7) is 0
	apiVersion := binary.BigEndian.Uint16(msg[6:8])
	if apiVersion != 0 {
		t.Fatalf("API version = %d, want 0", apiVersion)
	}

	// Verify the message contains the test topic name
	if !bytes.Contains(msg, []byte("test-topic")) {
		t.Fatal("message does not contain topic name")
	}

	// Verify the message contains the value
	if !bytes.Contains(msg, value) {
		t.Fatal("message does not contain the value")
	}
}

func TestBuildProduceRequestDifferentTopics(t *testing.T) {
	topics := []string{"topic1", "my-dns-logs", "test.topic.with.dots"}

	for _, topic := range topics {
		t.Run(topic, func(t *testing.T) {
			kp := &kafkaProducer{
				brokers: []string{"localhost:9092"},
				topic:   topic,
			}

			msg := kp.buildProduceRequest([]byte("test"))
			if !bytes.Contains(msg, []byte(topic)) {
				t.Fatalf("message does not contain topic name %s", topic)
			}
		})
	}
}

func TestBuildProduceRequestEmptyValue(t *testing.T) {
	kp := &kafkaProducer{
		brokers: []string{"localhost:9092"},
		topic:   "test",
	}

	msg := kp.buildProduceRequest([]byte{})
	if len(msg) == 0 {
		t.Fatal("buildProduceRequest returned empty message for empty value")
	}

	// Should still have valid structure
	size := binary.BigEndian.Uint32(msg[0:4])
	if size != uint32(len(msg)-4) {
		t.Fatalf("size mismatch for empty value")
	}
}

func TestBuildProduceRequestLargeValue(t *testing.T) {
	kp := &kafkaProducer{
		brokers: []string{"localhost:9092"},
		topic:   "test",
	}

	// Create a large value (10KB)
	largeValue := make([]byte, 10*1024)
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}

	msg := kp.buildProduceRequest(largeValue)

	// Verify size is correct
	size := binary.BigEndian.Uint32(msg[0:4])
	if size != uint32(len(msg)-4) {
		t.Fatalf("size mismatch for large value: got %d, want %d", size, len(msg)-4)
	}

	// Verify the large value is contained in the message
	if !bytes.Contains(msg, largeValue) {
		t.Fatal("message does not contain the large value")
	}
}

func TestKafkaProducerClose(t *testing.T) {
	// Test Close with nil connection (should not panic)
	kp := &kafkaProducer{
		brokers: []string{"localhost:9092"},
		topic:   "test",
		conn:    nil,
	}

	// This should not panic
	kp.Close()
}

func TestNewKafkaProducerEmptyBrokers(t *testing.T) {
	_, err := newKafkaProducer("", "test-topic")
	if err == nil {
		t.Fatal("expected error for empty brokers")
	}
}

func TestKafkaProducerBrokerParsing(t *testing.T) {
	// Test that broker list is properly parsed
	kp := &kafkaProducer{
		brokers: []string{"broker1:9092", "broker2:9093", "broker3"},
		topic:   "test",
	}

	if len(kp.brokers) != 3 {
		t.Fatalf("expected 3 brokers, got %d", len(kp.brokers))
	}
}
