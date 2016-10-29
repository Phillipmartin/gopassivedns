package main

import "bufio"
import "net"
import "fmt"
import "time"
import "strconv"
import "gopkg.in/natefinch/lumberjack.v2"
import "github.com/pquerna/ffjson/ffjson"
import log "github.com/Sirupsen/logrus"
import "github.com/quipo/statsd"

type logOptions struct {
	quiet        bool
	debug        bool
	Filename     string
	MaxAge		 int
	MaxBackups	 int
	MaxSize		 int
	KafkaBrokers string
	KafkaTopic   string
	closed       bool
	control      chan string
}

func NewLogOptions(config *pdnsConfig) *logOptions {
	return &logOptions{
		quiet:        config.quiet,
		debug:        config.debug,
		Filename:     config.logFile,
		KafkaBrokers: config.kafkaBrokers,
		KafkaTopic:   config.kafkaTopic,
		MaxAge:		  config.logMaxAge,
		MaxSize:	  config.logMaxSize,
		MaxBackups:	  config.logMaxBackups,
	}
}

func (lo *logOptions) IsDebug() bool {
	return lo.debug
}

func (lo *logOptions) LogToStdout() bool {
	return !lo.quiet
}

func (lo *logOptions) LogToFile() bool {
	return !(lo.Filename == "")
}

func (lo *logOptions) LogToKafka() bool {
	return !(lo.KafkaBrokers == "" && lo.KafkaTopic == "")
}

// codebeat:disable[TOO_MANY_IVARS]
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
// codebeat:enable[TOO_MANY_IVARS]

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

func initLogging(opts *logOptions) chan dnsLogEntry {
	if opts.IsDebug() {
		log.SetLevel(log.DebugLevel)
	}

	//TODO: further logging setup?

	/* spin up logging channel */
	var logChan = make(chan dnsLogEntry, 100)

	return logChan

}

func watchLogStats(stats *statsd.StatsdBuffer, logC chan dnsLogEntry, logs []chan dnsLogEntry) {
	for {
		stats.Gauge("incoming_log_depth", int64(len(logC)))
		for i, logChan := range logs {
			stats.Gauge(strconv.Itoa(i)+".log_depth", int64(len(logChan)))
		}

		time.Sleep(3)
	}
}

//Spin up required logging threads and then round-robin log messages to log sinks
func logConn(logC chan dnsLogEntry, opts *logOptions, stats *statsd.StatsdBuffer) {

	//holds the channels for the outgoing log channels
	var logs []chan dnsLogEntry

	if opts.LogToStdout() {
		log.Debug("STDOUT logging enabled")
		stdoutChan := make(chan dnsLogEntry)
		logs = append(logs, stdoutChan)
		go logConnStdout(stdoutChan)
	}

	if opts.LogToFile() {
		log.Debug("file logging enabled to " + opts.Filename)
		fileChan := make(chan dnsLogEntry)
		logs = append(logs, fileChan)
		go logConnFile(fileChan, opts)
	}

	if opts.LogToKafka() {
		log.Debug("kafka logging enabled")
		kafkaChan := make(chan dnsLogEntry)
		logs = append(logs, kafkaChan)
		go logConnKafka(kafkaChan, opts)
	}

	if stats != nil {
		go watchLogStats(stats, logC, logs)
	}

	//setup is done, now we sit here and dispatch messages to the configured sinks
	for message := range logC {
		for _, logChan := range logs {
			logChan <- message
		}
	}

	//if the range exits, the channel was closed, so close the other channels
	for _, logChan := range logs {
		close(logChan)
	}

	return
}

//logs to stdout
func logConnStdout(logC chan dnsLogEntry) {
	for message := range logC {
		encoded, _ := message.Encode()
		fmt.Println(string(encoded))
	}
}

//logs to a file
func logConnFile(logC chan dnsLogEntry, opts *logOptions) {

	logger := &lumberjack.Logger{
		Filename:   opts.Filename,
		MaxSize:    opts.MaxSize, // megabytes
		MaxBackups: opts.MaxBackups,
		MaxAge:     opts.MaxAge, //days
	}

	enc := ffjson.NewEncoder(bufio.NewWriter(logger))

	for message := range logC {
		enc.Encode(message)
	}

	logger.Close()

}

//logs to kafka
func logConnKafka(logC chan dnsLogEntry, opts *logOptions) {
	for message := range logC {
		encoded, _ := message.Encode()
		fmt.Println("Kafka: " + string(encoded))

	}
}
