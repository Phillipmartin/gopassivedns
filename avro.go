package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
)

// Avro Single Object Encoding support for dnsLogEntry.
//
// The format is: [0xC3, 0x01] + 8-byte CRC-64-AVRO fingerprint + Avro binary payload.
// See https://avro.apache.org/docs/1.11.1/specification/#single-object-encoding

// dnsLogEntryAvroSchema is the Avro schema for dnsLogEntry in Parsing Canonical Form.
// Fields are ordered to match the JSON tags used in dnsLogEntry.
const dnsLogEntryAvroSchema = `{"name":"DnsLogEntry","type":"record","fields":[{"name":"query_id","type":"int"},{"name":"rcode","type":"int"},{"name":"q","type":"string"},{"name":"qtype","type":"string"},{"name":"a","type":"string"},{"name":"atype","type":"string"},{"name":"ttl","type":"long"},{"name":"dst","type":"string"},{"name":"src","type":"string"},{"name":"tstamp","type":"string"},{"name":"elapsed","type":"long"},{"name":"sport","type":"string"},{"name":"level","type":"string"},{"name":"bytes","type":"int"},{"name":"protocol","type":"string"},{"name":"truncated","type":"boolean"},{"name":"aa","type":"boolean"},{"name":"rd","type":"boolean"},{"name":"ra","type":"boolean"}]}`

// avroMarker is the 2-byte header for Avro single object encoding (version 1).
var avroMarker = [2]byte{0xC3, 0x01}

// avroSchemaFingerprint is the precomputed CRC-64-AVRO of the schema's Parsing Canonical Form.
var avroSchemaFingerprint = func() [8]byte {
	initCRC64AvroTable()
	var fp [8]byte
	v := fingerprintCRC64Avro([]byte(dnsLogEntryAvroSchema))
	binary.LittleEndian.PutUint64(fp[:], v)
	return fp
}()

// AvroSchemaJSON returns the full (non-canonical) Avro schema as a JSON string
// suitable for registering with a schema registry.
func AvroSchemaJSON() string {
	return dnsLogEntryAvroSchema
}

// EncodeAvroSingleObject encodes a dnsLogEntry as an Avro Single Object.
func (dle *dnsLogEntry) EncodeAvroSingleObject() ([]byte, error) {
	payload := encodeAvroRecord(dle)
	buf := make([]byte, 0, 2+8+len(payload))
	buf = append(buf, avroMarker[:]...)
	buf = append(buf, avroSchemaFingerprint[:]...)
	buf = append(buf, payload...)
	return buf, nil
}

// encodeAvroRecord encodes a dnsLogEntry as Avro binary (no container/header).
func encodeAvroRecord(dle *dnsLogEntry) []byte {
	var buf []byte

	// query_id: int
	buf = appendAvroInt(buf, int32(dle.Query_ID))
	// rcode: int
	buf = appendAvroInt(buf, int32(dle.Response_Code))
	// q: string
	buf = appendAvroString(buf, dle.Question)
	// qtype: string
	buf = appendAvroString(buf, dle.Question_Type)
	// a: string
	buf = appendAvroString(buf, dle.Answer)
	// atype: string
	buf = appendAvroString(buf, dle.Answer_Type)
	// ttl: long
	buf = appendAvroLong(buf, int64(dle.TTL))
	// dst: string (IP as string)
	buf = appendAvroString(buf, dle.Server.String())
	// src: string (IP as string)
	buf = appendAvroString(buf, dle.Client.String())
	// tstamp: string
	buf = appendAvroString(buf, dle.Timestamp)
	// elapsed: long
	buf = appendAvroLong(buf, dle.Elapsed)
	// sport: string
	buf = appendAvroString(buf, dle.Client_Port)
	// level: string
	buf = appendAvroString(buf, dle.Level)
	// bytes: int
	buf = appendAvroInt(buf, int32(dle.Length))
	// protocol: string
	buf = appendAvroString(buf, dle.Proto)
	// truncated: boolean
	buf = appendAvroBool(buf, dle.Truncated)
	// aa: boolean
	buf = appendAvroBool(buf, dle.Authoritative_Answer)
	// rd: boolean
	buf = appendAvroBool(buf, dle.Recursion_Desired)
	// ra: boolean
	buf = appendAvroBool(buf, dle.Recursion_Available)

	return buf
}

// Avro variable-length integer encoding (zigzag + varint)

func appendAvroInt(buf []byte, v int32) []byte {
	return appendAvroLong(buf, int64(v))
}

func appendAvroLong(buf []byte, v int64) []byte {
	// zigzag encode
	z := uint64((v << 1) ^ (v >> 63))
	// varint encode
	for z >= 0x80 {
		buf = append(buf, byte(z)|0x80)
		z >>= 7
	}
	buf = append(buf, byte(z))
	return buf
}

func appendAvroString(buf []byte, s string) []byte {
	buf = appendAvroLong(buf, int64(len(s)))
	buf = append(buf, s...)
	return buf
}

func appendAvroBool(buf []byte, b bool) []byte {
	if b {
		return append(buf, 1)
	}
	return append(buf, 0)
}

// CRC-64-AVRO fingerprint algorithm per the Avro spec.
// Uses the Rabin fingerprint with EMPTY = 0xc15d213aa4d7a795.

const crc64AvroEmpty uint64 = 0xc15d213aa4d7a795

var crc64AvroTable [256]uint64
var crc64AvroTableReady bool

func initCRC64AvroTable() {
	if crc64AvroTableReady {
		return
	}
	for i := 0; i < 256; i++ {
		fp := uint64(i)
		for j := 0; j < 8; j++ {
			fp = (fp >> 1) ^ (crc64AvroEmpty & (-(fp & 1)))
		}
		crc64AvroTable[i] = fp
	}
	crc64AvroTableReady = true
}

func fingerprintCRC64Avro(data []byte) uint64 {
	fp := crc64AvroEmpty
	for _, b := range data {
		fp = (fp >> 8) ^ crc64AvroTable[(fp^uint64(b))&0xff]
	}
	return fp
}

// parseCanonicalForm converts the schema to Parsing Canonical Form.
// For this codebase we keep the schema constant pre-canonicalized,
// but this is available for verification.
func parseCanonicalForm(schema string) (string, error) {
	var obj interface{}
	if err := json.Unmarshal([]byte(schema), &obj); err != nil {
		return "", err
	}
	canonical := canonicalize(obj)
	out, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	// remove whitespace outside strings (json.Marshal is compact already)
	return strings.TrimSpace(string(out)), nil
}

// canonicalize recursively strips non-essential fields per the Avro spec.
var keepFields = map[string]bool{
	"name": true, "type": true, "fields": true, "symbols": true,
	"items": true, "values": true, "size": true,
}

func canonicalize(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{})
		for k, v2 := range val {
			if keepFields[k] {
				out[k] = canonicalize(v2)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, v2 := range val {
			out[i] = canonicalize(v2)
		}
		return out
	default:
		return v
	}
}
