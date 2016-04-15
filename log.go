package main

import "bufio"
import "net"
import "fmt"
import "gopkg.in/natefinch/lumberjack.v2"
import "github.com/pquerna/ffjson/ffjson"
import log "github.com/Sirupsen/logrus"


type dnsLogEntry struct {
	Query_ID      uint16 `json:"query_id"`
	Response_Code int    `json:"response_code"`
	Question      string `json:"question"`
	Question_Type string `json:"question_type"`
	Answer        string `json:"answer"`
	Answer_Type   string `json:"answer_type"`
	TTL           uint32 `json:"ttl"`
	Server        net.IP `json:"server"`
	Client        net.IP `json:"client"`
	Timestamp     string `json:"timestamp"`

	encoded []byte //to hold the marshaled data structure
	err     error  //encoding errors
}

//private, idempotent function that ensures the json is encoded
func (dle *dnsLogEntry) ensureEncoded() {
	if dle.encoded == nil && dle.err == nil {
		dle.encoded, dle.err = ffjson.Marshal(dle)
	}
}

//returns length of the encoded JSON
func (dle *dnsLogEntry) Length() int {
	dle.ensureEncoded()
	return len(dle.encoded)
}

//public method to encode the string
func (dle *dnsLogEntry) Encode() ([]byte, error) {
	dle.ensureEncoded()
	return dle.encoded, dle.err
}

func initLogging(debug bool) chan dnsLogEntry {
	if debug {
		log.SetLevel(log.DebugLevel)
	}

	//TODO: further logging setup?

	/* spin up logging channel */
	var logChan = make(chan dnsLogEntry, 100)

	return logChan

}

//Spin up required logging threads and then round-robin log messages to log sinks
func logConn(logC chan dnsLogEntry, quiet bool,
	filename string, kafkaBrokers string, kafkaTopic string) {

	//holds the channels for the outgoing log channels
	var logs []chan dnsLogEntry

	if !quiet {
		log.Debug("STDOUT logging enabled")
		stdoutChan := make(chan dnsLogEntry)
		logs = append(logs, stdoutChan)
		go logConnStdout(stdoutChan)
	}

	if filename != "" {
		log.Debug("file logging enabled to " + filename)
		fileChan := make(chan dnsLogEntry)
		logs = append(logs, fileChan)
		go logConnFile(fileChan, filename)
	}

	if kafkaBrokers != "" && kafkaTopic != "" && false {
		log.Debug("kafka logging enabled")
		kafkaChan := make(chan dnsLogEntry)
		logs = append(logs, kafkaChan)
		go logConnKafka(kafkaChan, kafkaBrokers, kafkaTopic)
	}

	//setup is done, now we sit here and dispatch messages to the configured sinks
	for message := range logC {
		for _, logChan := range logs {
			logChan <- message
		}
	}
}

//logs to stdout
func logConnStdout(logC chan dnsLogEntry) {
	for message := range logC {
		encoded, _ := message.Encode()
		fmt.Println(string(encoded))
	}
}

//logs to a file
func logConnFile(logC chan dnsLogEntry, filename string) {

	logger := &lumberjack.Logger{
	    Filename:   filename,
	    MaxSize:    1, // megabytes
	    MaxBackups: 3,
	    MaxAge:     28, //days
	}

	enc := ffjson.NewEncoder(bufio.NewWriter(logger))

	for message := range logC {
		enc.Encode(message)
	}
}

//logs to kafka
func logConnKafka(logC chan dnsLogEntry, kafkaBrokers string, kafkaTopic string) {
	for message := range logC {
		encoded, _ := message.Encode()
		fmt.Println("Kafka: " + string(encoded))
	}
}

