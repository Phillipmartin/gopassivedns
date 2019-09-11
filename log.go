package main

import (
	"bufio"
	"fmt"

	"log/syslog"
	"net"

	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/pquerna/ffjson/ffjson"
	"github.com/quipo/statsd"
	"github.com/vmihailenco/msgpack"
	"github.com/segmentio/kafka-go"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// codebeat:disable[TOO_MANY_IVARS]
type logOptions struct {
	quiet          bool
	debug          bool
	Filename       string
	FluentdSocket  string
	MaxAge         int
	MaxBackups     int
	MaxSize        int
	KafkaBrokers   string
	KafkaTopic     string
	SyslogFacility string
	SyslogPriority string
	SensorName     string
	closed         bool
	control        chan string
}

func NewLogOptions(config *pdnsConfig) *logOptions {
	return &logOptions{
		quiet:          config.quiet,
		debug:          config.debug,
		Filename:       config.logFile,
		FluentdSocket:  config.fluentdSocket,
		KafkaBrokers:   config.kafkaBrokers,
		KafkaTopic:     config.kafkaTopic,
		MaxAge:         config.logMaxAge,
		MaxSize:        config.logMaxSize,
		MaxBackups:     config.logMaxBackups,
		SyslogFacility: config.syslogFacility,
		SyslogPriority: config.syslogPriority,
		SensorName:     config.sensorName,
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

func (lo *logOptions) LogToSyslog() bool {
	return (lo.SyslogFacility != "" && lo.SyslogPriority != "")
}

func (lo *logOptions) LogToFluentd() bool {
	return (lo.FluentdSocket != "")
}

// codebeat:disable[TOO_MANY_IVARS]
type dnsLogEntry struct {
	Query_ID             uint16 `json:"query_id"`
	Response_Code        int    `json:"rcode"`
	Question             string `json:"q"`
	Question_Type        string `json:"qtype"`
	Answer               string `json:"a"`
	Answer_Type          string `json:"atype"`
	TTL                  uint32 `json:"ttl"`
	Server               net.IP `json:"dst"`
	Client               net.IP `json:"src"`
	Timestamp            string `json:"tstamp"`
	Elapsed              int64  `json:"elapsed"`
	Client_Port          string `json:"sport"`
	Level                string `json:"level"` // syslog level
	Length               int    `json:"bytes"`
	Proto                string `json:"protocol"`
	Truncated            bool   `json:"truncated"`
	Authoritative_Answer bool   `json:"aa"`
	Recursion_Desired    bool   `json:"rd"`
	Recursion_Available  bool   `json:"ra"`

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
func (dle *dnsLogEntry) Size() int {
	dle.ensureEncoded()
	return len(dle.encoded)
}

//public method to encode the string
func (dle *dnsLogEntry) Encode() ([]byte, error) {
	dle.ensureEncoded()
	return dle.encoded, dle.err
}

func initLogging(opts *logOptions, config *pdnsConfig) chan dnsLogEntry {
	if opts.IsDebug() {
		log.SetLevel(log.DebugLevel)
	}

	//TODO: further logging setup?

	/* spin up logging channel */
	var logChan = make(chan dnsLogEntry, packetQueue*config.numprocs)

	return logChan

}

func watchLogStats(stats *statsd.StatsdBuffer, logC chan dnsLogEntry, logs []chan dnsLogEntry) {
	for {
		stats.Gauge("incoming_log_depth", int64(len(logC)))
		for i, logChan := range logs {
			stats.Gauge(strconv.Itoa(i)+".log_depth", int64(len(logChan)))
		}

		time.Sleep(15 * time.Second)
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
		writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: opts.KafkaBrokers,
		Topic:   opts.KafkaTopic,
		Balancer: &kafka.LeastBytes{},
		})
		go logConnKafka(kafkaChan, opts, writer)
	}

	if opts.LogToSyslog() {
		log.Debug("syslog logging enabled")
		syslogChan := make(chan dnsLogEntry)
		logs = append(logs, syslogChan)
		go logConnSyslog(syslogChan, opts)
	}

	if opts.LogToFluentd() {
		log.Debug("fluentd logging enabled")
		fluentdlogChan := make(chan dnsLogEntry)
		logs = append(logs, fluentdlogChan)
		go logConnFluentd(fluentdlogChan, opts)
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
func logConnKafka(logC chan dnsLogEntry, opts *logOptions, writer) {
	for message := range logC {
		encoded, _ := message.Encode()
		writer.WriteMessages(context.Background(),
		kafka.Message{
			Value: []byte(encoded),
		},)
// 		fmt.Println("Kafka: " + string(encoded))

	}
}

//logs to syslog
func logConnSyslog(logC chan dnsLogEntry, opts *logOptions) {

	level, err := levelToType(opts.SyslogPriority)
	if err != nil {
		log.Fatalf("string '%s' did not parse as a priority", opts.SyslogPriority)
	}
	facility, err := facilityToType(opts.SyslogFacility)
	if err != nil {
		log.Fatalf("string '%s' did not parse as a facility", opts.SyslogFacility)
	}

	logger, err := syslog.New(facility|level, "")
	if err != nil {
		log.Fatalf("failed to connect to the local syslog daemon: %s", err)
	}

	for message := range logC {
		encoded, _ := message.Encode()
		logger.Write([]byte(encoded))
	}
}

//logs to fluentd via a unix socket
func logConnFluentd(logC chan dnsLogEntry, opts *logOptions) {
	Tag := opts.SensorName + ".service"
	tag, _ := msgpack.Marshal(Tag)

	conn := fluentdSocket(opts.FluentdSocket)
	defer conn.Close()

	for message := range logC {
		tm, _ := msgpack.Marshal(time.Now().Unix())
		rec, err := msgpack.Marshal(&message)

		if err != nil {
			fmt.Println(err)
		}

		encoded := []byte{0x93}
		encoded = append(encoded, tag...)
		encoded = append(encoded, tm...)
		encoded = append(encoded, rec...)

		_, err = conn.Write(encoded)

		if err != nil {
			log.Fatalf("Unable to write to UNIX Socket %+v with err %+v\n", opts.FluentdSocket, err)
		}
	}
}

func facilityToType(facility string) (syslog.Priority, error) {
	facility = strings.ToUpper(facility)
	switch facility {
	case "KERN":
		return syslog.LOG_KERN, nil
	case "USER":
		return syslog.LOG_USER, nil
	case "MAIL":
		return syslog.LOG_MAIL, nil
	case "DAEMON":
		return syslog.LOG_DAEMON, nil
	case "AUTH":
		return syslog.LOG_AUTH, nil
	case "SYSLOG":
		return syslog.LOG_SYSLOG, nil
	case "LPR":
		return syslog.LOG_LPR, nil
	case "NEWS":
		return syslog.LOG_NEWS, nil
	case "UUCP":
		return syslog.LOG_UUCP, nil
	case "CRON":
		return syslog.LOG_CRON, nil
	case "AUTHPRIV":
		return syslog.LOG_AUTHPRIV, nil
	case "FTP":
		return syslog.LOG_FTP, nil
	case "LOCAL0":
		return syslog.LOG_LOCAL0, nil
	case "LOCAL1":
		return syslog.LOG_LOCAL1, nil
	case "LOCAL2":
		return syslog.LOG_LOCAL2, nil
	case "LOCAL3":
		return syslog.LOG_LOCAL3, nil
	case "LOCAL4":
		return syslog.LOG_LOCAL4, nil
	case "LOCAL5":
		return syslog.LOG_LOCAL5, nil
	case "LOCAL6":
		return syslog.LOG_LOCAL6, nil
	case "LOCAL7":
		return syslog.LOG_LOCAL7, nil
	default:
		return 0, fmt.Errorf("invalid syslog facility: %s", facility)
	}
}

func levelToType(level string) (syslog.Priority, error) {
	level = strings.ToUpper(level)
	switch level {
	case "EMERG":
		return syslog.LOG_EMERG, nil
	case "ALERT":
		return syslog.LOG_ALERT, nil
	case "CRIT":
		return syslog.LOG_CRIT, nil
	case "ERR":
		return syslog.LOG_ERR, nil
	case "WARNING":
		return syslog.LOG_WARNING, nil
	case "NOTICE":
		return syslog.LOG_NOTICE, nil
	case "INFO":
		return syslog.LOG_INFO, nil
	case "DEBUG":
		return syslog.LOG_DEBUG, nil
	default:
		return 0, fmt.Errorf("Unknown priority: %s", level)
	}
}

func fluentdSocket(path string) *net.UnixConn {
	var retries int = 10
	var timeout time.Duration = 5

	// we want to have retries because fluentd can take some time to start.
	for i := 1; i <= retries; i++ {
		raddr, err := net.ResolveUnixAddr("unix", path)

		if err != nil {
			log.Printf("Failed to open remote socket. %s.\n", err)
		}

		conn, err := net.DialUnix("unix", nil, raddr)

		if err != nil {
			log.Printf("Failed to connect to fluentd socket. %s retrying in 5 seconds.", err)
			time.Sleep(timeout * time.Second)
			continue
		}

		err = conn.SetWriteBuffer(65536)

		if err != nil {
			log.Printf("Unable to set fluentd write buffer. %s", err)
		}

		return conn
	}

	log.Fatalf("Unable to open connection to fluentd socket after %d retries\n", retries)

	return nil
}
