package main

import "flag"
import "fmt"
import log "github.com/Sirupsen/logrus"
import "strconv"
import "time"
import "net"
import "os"
import "bufio"
import "runtime/pprof"
import "encoding/binary"

import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/pfring"
import "github.com/google/gopacket/layers"
import "github.com/pquerna/ffjson/ffjson"
/*
Plans:

    -code cleanup (e.g. break up handlePacket, switch everything to camelCase)
	deal with DNS Length header in TCP    
    -perf testing
    generate test pcaps
release v2

	flesh out more layer types
	stats output
	logging to kafka
release v3

    re-build error handling with panic()/recover()
    syslog logging
    add PF_RING support
    use something with a larger keyspace than the query ID for the conntable map
release v4

*/

/*

Structs and helper functions

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

/*
  struct for DNS connection table entry
  the 'inserted' value is used in connection table cleanup
*/
type dnsMapEntry struct {
//	question    []layers.DNS
//	question_length	 int
//	answer 	 []layers.DNS
//	answer_legnth	int
	entry	layers.DNS
	inserted time.Time
}


/*
   The gopacket DNS layer doesn't have a lot of good String()
   conversion methods, so we have to do a lot of that ourselves
   here.  Much of this should move back into gopacket.  Also a
   little worried about the perf impact of doing string conversions
   in this thread...
*/
func TypeString(dnsType layers.DNSType) string {
	switch dnsType {
	default:
		//take a blind stab...at least this shouldn't *lose* data
		return strconv.Itoa(int(dnsType))
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypeSRV:
		return "SRV"
	case 255: //ANY query per http://tools.ietf.org/html/rfc1035#page-12
		return "ANY"
	}
}

/*
   The gopacket DNS layer doesn't have a lot of good String()
   conversion methods, so we have to do a lot of that ourselves
   here.  Much of this should move back into gopacket.  Also a
   little worried about the perf impact of doing string conversions
   in this thread...
*/
func RrString(rr layers.DNSResourceRecord) string {
	switch rr.Type {
	default:
		//take a blind stab...at least this shouldn't *lose* data
		return string(rr.Data)
	case layers.DNSTypeA:
		return rr.IP.String()
	case layers.DNSTypeAAAA:
		return rr.IP.String()
	case layers.DNSTypeCNAME:
		return string(rr.CNAME)
	case layers.DNSTypeMX:
		//TODO: add the priority
		return string(rr.MX.Name)
	case layers.DNSTypeNS:
		return string(rr.NS)
	case layers.DNSTypePTR:
		return string(rr.PTR)
	case layers.DNSTypeTXT:
		return string(rr.TXT)
	case layers.DNSTypeSOA:
		//TODO: rebuild the full SOA string
		return string(rr.SOA.RName)
	case layers.DNSTypeSRV:
		//TODO: rebuild the full SRV string
		return string(rr.SRV.Name)
	}
}

/*
	takes the src IP, dst IP, DNS question, DNS reply and the logs struct to populate.
	returns nothing, but populates the logs array
*/
func initLogEntry(srcIP net.IP, dstIP net.IP, question layers.DNS, reply layers.DNS, logs *[]dnsLogEntry){
	
	/*
	   http://forums.devshed.com/dns-36/dns-packet-question-section-1-a-183026.html
	   multiple questions isn't really a thing, so we'll loop over the answers and
	   insert the question section from the original query.  This means a successful
	   ANY query may result in a lot of seperate log entries.  The query ID will be
	   the same on all of those entries, however, so you can rebuild the query that
	   way.

	   TODO: Also loop through Additional records in addition to Answers
	*/

	//a response code other than 0 means failure of some kind

	if reply.ResponseCode != 0 {

		*logs = append(*logs, dnsLogEntry{
			Query_ID:      reply.ID,
			Question:      string(question.Questions[0].Name),
			Response_Code: int(reply.ResponseCode),
			Question_Type: TypeString(question.Questions[0].Type),
			Answer:        reply.ResponseCode.String(),
			Answer_Type:   "",
			TTL:           0,
			//this is the answer packet, which comes from the server...
			Server: srcIP,
			//...and goes to the client
			Client:    dstIP,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})

	} else {
		for _, answer := range reply.Answers {

			*logs = append(*logs, dnsLogEntry{
				Query_ID:      reply.ID,
				Question:      string(question.Questions[0].Name),
				Response_Code: int(reply.ResponseCode),
				Question_Type: TypeString(question.Questions[0].Type),
				Answer:        RrString(answer),
				Answer_Type:   TypeString(answer.Type),
				TTL:           answer.TTL,
				//this is the answer packet, which comes from the server...
				Server: srcIP,
				//...and goes to the client
				Client:    dstIP,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		}
	}
}

//background task to clear out stale entries in the conntable
//one of these gets spun up for every packet handling thread
//takes a pointer to the contable to clean, the maximum age of an entry and how often to run GC
func cleanDnsCache(conntable *map[uint16]dnsMapEntry, maxAge time.Duration, interval time.Duration) {

	for {
		time.Sleep(interval)

		//max_age should be negative, e.g. -1m
		cleanupCutoff := time.Now().Add(maxAge)
		for key, item := range *conntable {
			if item.inserted.Before(cleanupCutoff) {
				log.Debug("conntable GC: cleanup query ID " + strconv.Itoa(int(key)))
				delete(*conntable, key)
			}
		}
	}
}

/* validate if DNS packet, make conntable entry and output
   to log channel if there is a match
   
   we pass packet by value here because we turned on ZeroCopy for the capture, which reuses the capture buffer
*/
func handlePacket(packets chan gopacket.Packet, logC chan dnsLogEntry,
	gcInterval time.Duration, gcAge time.Duration) {

	//DNS IDs are stored as uint16s by the gopacket DNS layer
	var conntable = make(map[uint16]dnsMapEntry)

	//setup garbage collection for this map
	go cleanDnsCache(&conntable, gcAge, gcInterval)

	var ethLayer layers.Ethernet
    var ipLayer  layers.IPv4
    var udpLayer layers.UDP
    var tcpLayer layers.TCP
    var dns layers.DNS
    var payload gopacket.Payload
	
	//pre-allocated for initLogEntry
	logs := []dnsLogEntry{}
	
	parser := gopacket.NewDecodingLayerParser(
            layers.LayerTypeEthernet,
            &ethLayer,
            &ipLayer,
            &udpLayer,
            &tcpLayer,
            &dns,
            &payload,
        )
	
	dnsParser := gopacket.NewDecodingLayerParser(
            layers.LayerTypeDNS,
            &dns,
            &payload,
        )
	
	foundLayerTypes := []gopacket.LayerType{}

	for packet := range packets {
		
		parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		
		if foundLayerType(layers.LayerTypeTCP, foundLayerTypes) && 
			!foundLayerType(gopacket.LayerTypePayload, foundLayerTypes){
			//TCP control packet, skip
			continue
		}
		
		//TODO: Actually use the legnth field and store response if it's less than the length
		
		//If we have a TCP packet with a payload fix our offset and re-parse
		if foundLayerType(layers.LayerTypeTCP, foundLayerTypes) &&  
			foundLayerType(gopacket.LayerTypePayload, foundLayerTypes){
			//in DNS over TCP a 16 bit length field is prepended to the packet
			//gopacket utterly fails at handling this case, so we help it out.
			
			//for the future int(payload[:2]) is the total legnth of the response
			//the legnth is the length of the packet in bytes -2 (for the 2 length bytes)
			err := dnsParser.DecodeLayers(payload[2:], &foundLayerTypes)
			
			if err != nil {
        		log.Debug("Trouble decoding TCP DNS layers: ", err)
            	log.Debug("Packet: "+packet.String())
            	continue
        	}
        	
        	if len(payload)-2 != int(binary.BigEndian.Uint16(payload[:8])) {
        		log.Debug("multi-packet DNS response found but not yet implemented")
        	}
		}
		
		//If we have a packet that's not DNS but DOES have a payload
		//Debug it and move on
		if !foundLayerType(layers.LayerTypeDNS, foundLayerTypes) && 
			foundLayerType(gopacket.LayerTypePayload, foundLayerTypes){
			log.Debug("Got a packet with a payload but without a DNS Layer: "+packet.String())
			continue
		}
		
		srcIP := ipLayer.SrcIP 
		dstIP := ipLayer.DstIP
		
		//skip non-query stuff (Updates, AXFRs, etc)
		if dns.OpCode != layers.DNSOpCodeQuery {
			log.Debug("Saw non-update DNS packet: " + packet.String())
			continue
		}

		item, foundItem := conntable[dns.ID]

		//this is a Query Response packet
		if dns.QR && foundItem {
			question := item.entry
			//We have both legs of the connection, so drop the connection from the table
			//log.Debug("Got 'answer' leg of query ID: " + strconv.Itoa(int(question.ID)))
			delete(conntable, question.ID)
			
			logs = nil
			initLogEntry(srcIP, dstIP, question, dns, &logs)

			//TODO: send the array itself, not the elements of the array
			//to reduce the number of channel transactions
			for _, logEntry := range logs {
				logC <- logEntry
			}

		} else if dns.QR && !foundItem {
			//This might happen if we get a query ID collision
			log.Debug("Got a Query Response and can't find a query for ID " + strconv.Itoa(int(dns.ID)))
			continue
		} else {
			//This is the initial query.  save it for later.
			//log.Debug("Got the 'question' leg of query ID " + strconv.Itoa(int(dns.ID)))
			mapEntry := dnsMapEntry{
				entry:    dns,
				inserted: time.Now(),
			}
			conntable[dns.ID] = mapEntry
		}
	}
}

//Round-robin log messages to log sinks
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

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Debug("could not open logfile "+filename+" for writing!")
		panic(err)
	}

	defer f.Close()

	enc := ffjson.NewEncoder(bufio.NewWriter(f))

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

//setup a device or pcap file for capture, returns a handle
func initHandle(dev string, pcapFile string, bpf string, pfring bool) *pcap.Handle {

	var handle *pcap.Handle
	var err error

	if dev != "" && !pfring {
		handle, err = pcap.OpenLive(dev, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Debug(err)
			return nil
		}
	} else if dev != "" && pfring {
		handle, err = pfring.NewRing(dev, 65536, true, pfring.FlagPromisc)
		if err != nil {
			log.Debug(err)
			return nil
		}
	} else if pcapFile != "" {
		handle, err = pcap.OpenOffline(pcapFile)
		if err != nil {
			log.Debug(err)
			return nil
		}
	} else {
		log.Debug("You must specify either a capture device or a pcap file")
		return nil
	}

	err = handle.SetBPFFilter(bpf)
	if err != nil {
		log.Debug(err)
		return nil
	}
	
	if dev != "" && pfring {
		handle.Enable()
	}

	return handle
}

func foundLayerType(layer gopacket.LayerType, found []gopacket.LayerType) bool{
	for _, value := range found {
		if value == layer {
			return true
		}
	}
	
	return false
}

//kick off packet procesing threads and start the packet capture loop
func doCapture(handle *pcap.Handle, logChan chan dnsLogEntry,
	gcAge string, gcInterval string, numprocs int) {

	gcAgeDur, err := time.ParseDuration(gcAge)

	if err != nil {
		log.Fatal("Your gc_age parameter was not parseable.  Use a string like '-1m'")
	}

	gcIntervalDur, err := time.ParseDuration(gcInterval)

	if err != nil {
		log.Fatal("Your gc_age parameter was not parseable.  Use a string like '3m'")
	}

	/* init channels for the packet handlers and kick off handler threads */
	var channels []chan gopacket.Packet
	for i := 0; i < numprocs; i++ {
		channels = append(channels, make(chan gopacket.Packet, 100))
	}

	for i := 0; i < numprocs; i++ {
		go handlePacket(channels[i], logChan, gcIntervalDur, gcAgeDur)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//only decode packet in response to function calls, this moves the
	//packet processing to the processing threads
	packetSource.DecodeOptions.Lazy = true
	//We don't mutate bytes of the packets, so no need to make a copy
	//this does mean we need to pass the packet via the channel, not a pointer to the packet
	//as the underlying buffer will get re-allocated
	packetSource.DecodeOptions.NoCopy = true

	/*
		parse up to the IP layer so we can consistently balance the packets across our 
		processing threads
		
		TODO: in the future maybe pass this on the channel to so we don't reparse
				but the profiling I've done doesn't point to this as a problem
	*/

	var ethLayer layers.Ethernet
    var ipLayer  layers.IPv4
	
	parser := gopacket.NewDecodingLayerParser(
            layers.LayerTypeEthernet,
            &ethLayer,
            &ipLayer,
        )
	
	foundLayerTypes := []gopacket.LayerType{}

	for packet := range packetSource.Packets() {
		/*  load balance the processiing over N threads
		    FashHash is consistant for A->B and B->A hashes, which simplifies
		    our connection tracking problem a bit by letting us keep
		    per-worker connection pools instead of a global pool.
		*/
			
		parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		
		if foundLayerType(layers.LayerTypeIPv4, foundLayerTypes) {
			channels[int(ipLayer.NetworkFlow().FastHash()) & (numprocs-1)] <- packet
		}else{
    		log.Debug("Saw a non-IPv4 Packet: "+packet.String())
		}
    	
	}
}

//setup logging settings
func initLogging(debug bool) chan dnsLogEntry {
	if debug {
		log.SetLevel(log.DebugLevel)
	}

	//TODO: further logging setup?

	/* spin up logging channel */
	var logChan = make(chan dnsLogEntry, 100)

	return logChan

}

func main() {

	var dev = flag.String("dev", "", "Capture Device")
	var kafkaBrokers = flag.String("kafka_brokers", os.Getenv("KAFKA_PEERS"), "The Kafka brokers to connect to, as a comma separated list")
	var kafkaTopic = flag.String("kafka_topic", "", "Kafka topic for output")
	var bpf = flag.String("bpf", "port 53", "BPF Filter")
	var pcapFile = flag.String("pcap", "", "pcap file")
	var logFile = flag.String("logfile", "", "log file (recommended for debug only")
	var quiet = flag.Bool("quiet", false, "do not log to stdout")
	var gcAge = flag.String("gc_age", "-1m", "How old a connection table entry should be before it is garbage collected.")
	var gcInterval = flag.String("gc_interval", "3m", "How often to run garbage collection.")
	var debug = flag.Bool("debug", false, "Enable debug logging")
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	var numprocs = flag.Int("numprocs", 8, "number of packet processing threads")
	var pfring = flag.Bool("pfring", false, "Capture using PF_RING")

	flag.Parse()

	if *cpuprofile != "" {
        f, err := os.Create(*cpuprofile)
        if err != nil {
            log.Fatal(err)
        }
        pprof.StartCPUProfile(f)
        defer pprof.StopCPUProfile()
    }

	handle := initHandle(*dev, *pcapFile, *bpf, *pfring)

	if handle == nil {
		log.Fatal("Could not initilize the capture.")
	}

	logChan := initLogging(*debug)

	//spin up logging thread(s)
	go logConn(logChan, *quiet, *logFile, *kafkaBrokers, *kafkaTopic)

	//spin up the actual capture threads
	doCapture(handle, logChan, *gcAge, *gcInterval, *numprocs)

}
