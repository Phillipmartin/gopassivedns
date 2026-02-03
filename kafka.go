package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
)

// Minimal Kafka producer implementing the Kafka 0.8+ Produce Request (API key 0).
// This avoids pulling in heavy dependencies like sarama.

const (
	kafkaAPIKeyProduce  int16 = 0
	kafkaAPIVersion     int16 = 0
	kafkaCorrelationID        = 1
	kafkaClientID             = "gopassivedns"
	kafkaRequiredAcks   int16 = 1
	kafkaProduceTimeout int32 = 5000 // ms
)

type kafkaProducer struct {
	brokers []string
	topic   string
	conn    net.Conn
}

func newKafkaProducer(brokers, topic string) (*kafkaProducer, error) {
	brokerList := strings.Split(brokers, ",")
	if len(brokerList) == 0 || brokers == "" {
		return nil, fmt.Errorf("no kafka brokers specified")
	}

	kp := &kafkaProducer{
		brokers: brokerList,
		topic:   topic,
	}

	if err := kp.connect(); err != nil {
		return nil, err
	}

	return kp, nil
}

func (kp *kafkaProducer) connect() error {
	var lastErr error
	for _, broker := range kp.brokers {
		broker = strings.TrimSpace(broker)
		if !strings.Contains(broker, ":") {
			broker = broker + ":9092"
		}
		conn, err := net.DialTimeout("tcp", broker, 10*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		kp.conn = conn
		log.Debugf("Connected to Kafka broker %s", broker)
		return nil
	}
	return fmt.Errorf("failed to connect to any kafka broker: %v", lastErr)
}

func (kp *kafkaProducer) reconnect() error {
	if kp.conn != nil {
		kp.conn.Close()
		kp.conn = nil
	}
	return kp.connect()
}

// Send sends a single message (value only, no key) to the configured topic, partition 0.
func (kp *kafkaProducer) Send(value []byte) error {
	msg := kp.buildProduceRequest(value)

	for attempt := 0; attempt < 3; attempt++ {
		if kp.conn == nil {
			if err := kp.reconnect(); err != nil {
				time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
				continue
			}
		}

		kp.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err := kp.conn.Write(msg)
		if err != nil {
			log.Debugf("Kafka write failed: %s, reconnecting...", err)
			kp.conn.Close()
			kp.conn = nil
			time.Sleep(time.Duration(1<<uint(attempt)) * time.Second)
			continue
		}

		// Read produce response (we asked for acks=1)
		kp.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		respSizeBuf := make([]byte, 4)
		if _, err := readFull(kp.conn, respSizeBuf); err != nil {
			log.Debugf("Kafka read response size failed: %s", err)
			kp.conn.Close()
			kp.conn = nil
			continue
		}

		respSize := int(binary.BigEndian.Uint32(respSizeBuf))
		if respSize > 0 && respSize < 1<<20 {
			resp := make([]byte, respSize)
			readFull(kp.conn, resp)
			// We don't parse the response in detail — a successful read is good enough
		}

		return nil
	}

	return fmt.Errorf("failed to send message after 3 attempts")
}

func (kp *kafkaProducer) Close() {
	if kp.conn != nil {
		kp.conn.Close()
	}
}

// buildProduceRequest builds a Kafka Produce Request v0 with a single message.
// Wire format:
//
//	Size (4 bytes, not counted in size) | APIKey(2) | APIVersion(2) | CorrelationID(4) |
//	ClientID(2+len) | RequiredAcks(2) | Timeout(4) |
//	TopicCount(4) | TopicName(2+len) | PartitionCount(4) | Partition(4) |
//	MessageSetSize(4) | MessageSet...
func (kp *kafkaProducer) buildProduceRequest(value []byte) []byte {
	// Build message (inside MessageSet)
	// Message: Offset(8) + MessageSize(4) + CRC(4) + MagicByte(1) + Attributes(1) + Key(-1 = null, 4 bytes) + ValueLen(4) + Value
	msgBody := make([]byte, 0, 6+4+len(value))
	msgBody = append(msgBody, 0, 0, 0, 0) // CRC placeholder
	msgBody = append(msgBody, 0)           // MagicByte = 0
	msgBody = append(msgBody, 0)           // Attributes = 0 (no compression)
	// Key = null (-1)
	msgBody = appendInt32(msgBody, -1)
	// Value
	msgBody = appendInt32(msgBody, int32(len(value)))
	msgBody = append(msgBody, value...)

	// Compute CRC32 over bytes 4..end (after the CRC field)
	crc := crc32Kafka(msgBody[4:])
	binary.BigEndian.PutUint32(msgBody[0:4], crc)

	// MessageSet entry: Offset(8) + MessageSize(4) + Message
	messageSet := make([]byte, 0, 12+len(msgBody))
	messageSet = appendInt64(messageSet, 0) // offset (ignored by broker for produce)
	messageSet = appendInt32(messageSet, int32(len(msgBody)))
	messageSet = append(messageSet, msgBody...)

	// Build full request
	topicBytes := []byte(kp.topic)
	clientIDBytes := []byte(kafkaClientID)

	// Calculate total request body size
	bodySize := 2 + 2 + 4 + // APIKey + APIVersion + CorrelationID
		2 + len(clientIDBytes) + // ClientID
		2 + 4 + // RequiredAcks + Timeout
		4 + // TopicCount
		2 + len(topicBytes) + // TopicName
		4 + // PartitionCount
		4 + // Partition
		4 + // MessageSetSize
		len(messageSet)

	buf := make([]byte, 0, 4+bodySize)
	buf = appendInt32(buf, int32(bodySize))
	buf = appendInt16(buf, kafkaAPIKeyProduce)
	buf = appendInt16(buf, kafkaAPIVersion)
	buf = appendInt32(buf, kafkaCorrelationID)
	// ClientID
	buf = appendInt16(buf, int16(len(clientIDBytes)))
	buf = append(buf, clientIDBytes...)
	// RequiredAcks
	buf = appendInt16(buf, kafkaRequiredAcks)
	// Timeout
	buf = appendInt32(buf, kafkaProduceTimeout)
	// TopicCount
	buf = appendInt32(buf, 1)
	// TopicName
	buf = appendInt16(buf, int16(len(topicBytes)))
	buf = append(buf, topicBytes...)
	// PartitionCount
	buf = appendInt32(buf, 1)
	// Partition 0
	buf = appendInt32(buf, 0)
	// MessageSetSize
	buf = appendInt32(buf, int32(len(messageSet)))
	buf = append(buf, messageSet...)

	return buf
}

func appendInt16(buf []byte, v int16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

func appendInt32(buf []byte, v int32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendInt64(buf []byte, v int64) []byte {
	return append(buf, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		nn, err := conn.Read(buf[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// crc32Kafka computes CRC32 with the polynomial used by Kafka (IEEE/Castagnoli).
func crc32Kafka(data []byte) uint32 {
	// Kafka uses CRC-32C (Castagnoli) but the v0 message format uses IEEE CRC32.
	// For v0 produce requests, IEEE is correct.
	var crc uint32 = 0xFFFFFFFF
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xFFFFFFFF
}
