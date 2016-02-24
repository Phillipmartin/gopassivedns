package main

import "flag"
import "fmt"
import log "github.com/Sirupsen/logrus"
import "strconv"
import "time"
import "net"
import "os"
import "encoding/json"

//import "github.com/Shopify/sarama"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"

/*
Plans:

    code cleanup (e.g. switch everything to camelCase)
    stats output
    perf testing
    TCP flow support
release v2

    logging to kafka
    add PF_RING support
release v3

    maybe use something with a larger keyspace than the query ID for the conntable map
    maybe not so many string conversions?
    add more Types to gopacket
*/

/*

DNS log entry struct and helper functions

*/
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

func (dle *dnsLogEntry) ensureEncoded() {
	if dle.encoded == nil && dle.err == nil {
		dle.encoded, dle.err = json.Marshal(dle)
	}
}

func (dle *dnsLogEntry) Length() int {
	dle.ensureEncoded()
	return len(dle.encoded)
}

func (dle *dnsLogEntry) Encode() ([]byte, error) {
	dle.ensureEncoded()
	return dle.encoded, dle.err
}

type dnsMapEntry struct {
	entry    *layers.DNS
	inserted time.Time
}

//background task to clear out stale entries in the conntable
//one of these gets spun up for every packet handling thread
func cleanDnsCache(conntable *map[uint16]dnsMapEntry, max_age time.Duration, interval time.Duration) {

	for {
		time.Sleep(interval)

		//max_age should be negative, e.g. -1m
		cleanup_cutoff := time.Now().Add(max_age)
		for key, item := range *conntable {
			if item.inserted.Before(cleanup_cutoff) {
				log.Debug("conntable GC: cleanup query ID " + strconv.Itoa(int(key)))
				delete(*conntable, key)
			}
		}
	}
}

/* validate if DNS, make conntable entry and output
   to log channel if there is a match
*/
func handlePacket(packets chan gopacket.Packet, logC chan dnsLogEntry,
	gc_interval time.Duration, gc_age time.Duration) {

	//DNS IDs are stored as uint16s by the gopacket DNS layer
	//TODO: fix the memory leak of failed lookups by making this a ttlcache
	var conntable = make(map[uint16]dnsMapEntry)

	//setup garbage collection for this map
	go cleanDnsCache(&conntable, gc_age, gc_interval)

	for packet := range packets {
		//TODO: there must be a better way of doing this with gopacket
		var srcIP net.IP
		var dstIP net.IP

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ipData, _ := ipLayer.(*layers.IPv4)
			srcIP = ipData.SrcIP
			dstIP = ipData.DstIP
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			ipData, _ := ipLayer.(*layers.IPv6)
			srcIP = ipData.SrcIP
			dstIP = ipData.DstIP
		} else {
			//non-IP transport?  Ignore this packet
			log.Debug("Got non-IP packet: " + packet.String())
			continue
		}

		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			// Get actual DNS data from this layer
			dns, _ := dnsLayer.(*layers.DNS)

			//skip non-query stuff (Updates, AXFRs, etc)
			if dns.OpCode != layers.DNSOpCodeQuery {
				log.Debug("Saw non-update DNS packet: " + packet.String())
				continue
			}

			//this is a Query Response packet
			if dns.QR == true {
				if item, ok := conntable[dns.ID]; ok != false {
					question := item.entry
					//We have both legs of the connection, so drop the connection from the table
					log.Debug("Got 'answer' leg of query ID: " + strconv.Itoa(int(question.ID)))
					delete(conntable, question.ID)

					/*
					   http://forums.devshed.com/dns-36/dns-packet-question-section-1-a-183026.html
					   multiple questions isn't really a thing, so we'll loop over the answers and
					   insert the question section from the original query.  This means a successful
					   ANY query may result in a lot of seperate log entries.  The query ID will be
					   the same on all of those entries, however, so you can rebuild the query that
					   way.

					   TODO: Also loop through Additional records in addition to Answers
					*/

					/*
					   The gopacket DNS layer doesn't have a lot of good String()
					   conversion methods, so we have to do a lot of that ourselves
					   here.  Much of this should move back into gopacket.  Also a
					   little worried about the perf impact of doing string conversions
					   in this thread...

					*/

					var questionType string

					switch question.Questions[0].Type {
					default:
						log.Debug("Got unknown record type: " + strconv.Itoa(int(question.Questions[0].Type)))
						questionType = strconv.Itoa(int(question.Questions[0].Type))
					case layers.DNSTypeA:
						questionType = "A"
					case layers.DNSTypeAAAA:
						questionType = "AAAA"
					case layers.DNSTypeCNAME:
						questionType = "CNAME"
					case layers.DNSTypeMX:
						questionType = "MX"
					case layers.DNSTypeNS:
						questionType = "NS"
					case layers.DNSTypePTR:
						questionType = "PTR"
					case layers.DNSTypeTXT:
						questionType = "TXT"
					case layers.DNSTypeSOA:
						questionType = "SOA"
					case layers.DNSTypeSRV:
						questionType = "SRV"
					case 255: //ANY query per http://tools.ietf.org/html/rfc1035#page-12
						questionType = "ANY"
					}

					//a response code of 0 means success
					if dns.ResponseCode != 0 {

						logEntry := dnsLogEntry{
							Query_ID:      dns.ID,
							Question:      string(question.Questions[0].Name),
							Response_Code: int(dns.ResponseCode),
							Question_Type: questionType,
							Answer:        dns.ResponseCode.String(),
							Answer_Type:   "",
							TTL:           0,
							//this is the answer packet, which comes from the server...
							Server: srcIP,
							//...and goes to the client
							Client:    dstIP,
							Timestamp: time.Now().UTC().Format(time.RFC3339),
						}

						logC <- logEntry

						continue

					}

					for _, answer := range dns.Answers {

						var answerString string
						var typeString string

						switch answer.Type {
						default:
							//take a blind stab...at least this shouldn't *lose* data
							answerString = string(answer.Data)
							typeString = strconv.Itoa(int(answer.Type))
						case layers.DNSTypeA:
							answerString = answer.IP.String()
							typeString = "A"
						case layers.DNSTypeAAAA:
							answerString = answer.IP.String()
							typeString = "AAAA"
						case layers.DNSTypeCNAME:
							answerString = string(answer.CNAME)
							typeString = "CNAME"
						case layers.DNSTypeMX:
							//TODO: add the priority
							answerString = string(answer.MX.Name)
							typeString = "MX"
						case layers.DNSTypeNS:
							answerString = string(answer.NS)
							typeString = "NS"
						case layers.DNSTypePTR:
							answerString = string(answer.PTR)
							typeString = "PTR"
						case layers.DNSTypeTXT:
							answerString = string(answer.TXT)
							typeString = "TXT"
						case layers.DNSTypeSOA:
							//TODO: rebuild the full SOA string
							answerString = string(answer.SOA.RName)
							typeString = "SOA"
						case layers.DNSTypeSRV:
							//TODO: rebuild the full SRV string
							answerString = string(answer.SRV.Name)
							typeString = "SRV"
						}

						logEntry := dnsLogEntry{
							Query_ID:      dns.ID,
							Question:      string(question.Questions[0].Name),
							Response_Code: int(dns.ResponseCode),
							Question_Type: questionType,
							Answer:        answerString,
							Answer_Type:   typeString,
							TTL:           answer.TTL,
							//this is the answer packet, which comes from the server...
							Server: srcIP,
							//...and goes to the client
							Client:    dstIP,
							Timestamp: time.Now().UTC().Format(time.RFC3339),
						}

						logC <- logEntry

					}
				} else {
					//This might happen if we get a query ID collision
					log.Debug("Got a Query Response and can't find a query for ID " + strconv.Itoa(int(dns.ID)))
					continue
				}
			} else {
				//This is the initial query.  save it for later.
				log.Debug("Got the 'question' leg of query ID " + strconv.Itoa(int(dns.ID)))
				mapEntry := dnsMapEntry{
					entry:    dns,
					inserted: time.Now(),
				}
				conntable[dns.ID] = mapEntry
			}
		}
	}
}

//Round-robin log messages to log sinks
func logConn(logC chan dnsLogEntry, stdout bool, file bool, kafka bool,
	filename string, kafka_brokers string, kafka_topic string) {

	var logs []chan dnsLogEntry

	if stdout {
		log.Debug("STDOUT logging enabled")
		stdoutChan := make(chan dnsLogEntry)
		logs = append(logs, stdoutChan)
		go logConnStdout(stdoutChan)
	}

	if file {
		log.Debug("file logging enabled to " + filename)
		fileChan := make(chan dnsLogEntry)
		logs = append(logs, fileChan)
		go logConnFile(fileChan, filename)
	}

	if kafka && false {
		log.Debug("kafka logging enabled")
		kafkaChan := make(chan dnsLogEntry)
		logs = append(logs, kafkaChan)
		go logConnKafka(kafkaChan, kafka_brokers, kafka_topic)
	}

	//setup is done, now we sit here and dispatch messages to the configured sinks
	for message := range logC {
		for _, logChan := range logs {
			logChan <- message
		}
	}
}

func logConnStdout(logC chan dnsLogEntry) {
	for message := range logC {
		encoded, _ := message.Encode()
		fmt.Println(string(encoded))
	}
}

func logConnFile(logC chan dnsLogEntry, filename string) {

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Debug("could not open logfile for writing!")
		panic(err)
	}

	defer f.Close()

	for message := range logC {
		encoded, _ := message.Encode()
		f.WriteString(string(encoded) + "\n")
	}
}

func logConnKafka(logC chan dnsLogEntry, kafka_brokers string, kafka_topic string) {
	for message := range logC {
		//marshal to JSON.  Maybe we should do this in the log thread?
		encoded, _ := message.Encode()
		fmt.Println("Kafka: " + string(encoded))
	}
}

func main() {

	var dev = flag.String("dev", "", "Capture Device")
	var kafka_brokers = flag.String("kafka_brokers", os.Getenv("KAFKA_PEERS"), "The Kafka brokers to connect to, as a comma separated list")
	var kafka_topic = flag.String("kafka_topic", "", "Kafka topic for output")
	var bpf = flag.String("bpf", "port 53", "BPF Filter")
	var pcapFile = flag.String("pcap", "", "pcap file")
	var logfile = flag.String("logfile", "", "log file (recommended for debug only")
	var quiet = flag.Bool("quiet", false, "do not log to stdout")
	var gc_age = flag.String("gc_age", "-1m", "How old a connection table entry should be before it is garbage collected.")
	var gc_interval = flag.String("gc_interval", "3m", "How often to run garbage collection.")
	var debug = flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()

	var handle *pcap.Handle
	var err error

	if *dev != "" {
		handle, err = pcap.OpenLive(*dev, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
	} else if *pcapFile != "" {
		handle, err = pcap.OpenOffline(*pcapFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatal("You must specify either a capture device or a pcap file")
	}

	defer handle.Close()

	err = handle.SetBPFFilter(*bpf)
	if err != nil {
		log.Fatal(err)
	}

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	/* spin up logging thread */
	var logChan = make(chan dnsLogEntry)
	var log_file bool = false
	var log_kafka bool = false

	if *logfile != "" {
		log_file = true
	}

	if *kafka_brokers != "" && *kafka_topic != "" {
		log_kafka = true
	}

	var gc_age_dur time.Duration
	var gc_interval_dur time.Duration

	if gc_age_tmp, err := time.ParseDuration(*gc_age); err != nil {
		log.Fatal("Your gc_age parameter was not parseable.  Use a string like '-1m'")
	} else {
		gc_age_dur = gc_age_tmp
	}

	if gc_interval_tmp, err := time.ParseDuration(*gc_interval); err != nil {
		log.Fatal("Your gc_age parameter was not parseable.  Use a string like '3m'")
	} else {
		gc_interval_dur = gc_interval_tmp
	}

	go logConn(logChan, !*quiet, log_file, log_kafka, *logfile, *kafka_brokers, *kafka_topic)

	/* init channels for the packet handlers and kick off handler threads */
	var channels [8]chan gopacket.Packet
	for i := 0; i < 8; i++ {
		channels[i] = make(chan gopacket.Packet)
		go handlePacket(channels[i], logChan, gc_interval_dur, gc_age_dur)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Dispatch packets here
		if net := packet.NetworkLayer(); net != nil {
			/*  load balance the processiing over 8 threads
			    FashHash is consistant for A->B and B->A hashes, which simplifies
			    our connection tracking problem a bit by letting us keep
			    per-worker connection pools instead of a global pool.
			*/
			channels[int(net.NetworkFlow().FastHash())&0x7] <- packet
		}
	}
}
