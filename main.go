package main

import "flag"
import log "github.com/Sirupsen/logrus"
import "strconv"
import "time"
import "net"
import "os"
import "io"
import "runtime/pprof"
import "encoding/binary"

import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/tcpassembly"
import "github.com/google/gopacket/tcpassembly/tcpreader"
//import "github.com/google/gopacket/pfring"
import "github.com/google/gopacket/layers"


/*

Structs and helper functions

*/


/*
  struct for DNS connection table entry
  the 'inserted' value is used in connection table cleanup
*/
type dnsMapEntry struct {
	entry	layers.DNS
	inserted time.Time
}

/*
  struct to store reassembled TCP streams
*/
type tcpDataStruct struct {
	DnsData []byte
	IpLayer	gopacket.Flow
	Length	int
}

/*
  struct to store either reassembled TCP streams or packets
  Type will be tcp or packet for those type
  or it can be 'flush' or 'stop' to signal packet handling threads
*/
type packetData struct {
	Packet gopacket.Packet
	Tcpdata tcpDataStruct
	Type string
}

/*
  global channel to recieve reassembled TCP streams
  consumed in doCapture
*/
var reassembleChan chan tcpDataStruct

/*
  TCP reassembly stuff, all the work is done in run()
*/

type dnsStreamFactory struct{}

type dnsStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (d *dnsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	dstream := &dnsStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go dstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &dstream.r
}

func (d *dnsStream) run() {
	var data []byte
	var tmp = make([]byte, 4096)
	
	for {
		count, err := d.r.Read(tmp)
		
		if err == io.EOF {  
			//we must read to EOF, so we also use it as a signal to send the reassembed
			//stream into the channel
			reassembleChan <- tcpDataStruct{
				DnsData: data[2:int(binary.BigEndian.Uint16(data[:2]))+2], 
				IpLayer: d.net,
				Length: int(binary.BigEndian.Uint16(data[:2])),
			}
			return
		}else if err != nil {
			log.Debug("Error when reading DNS buf: ", err)
		}else if count > 0 {
			
			data = append(data, tmp...)
		
		}
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
func cleanDnsCache(conntable *map[uint16]dnsMapEntry, maxAge time.Duration, interval time.Duration, threadNum int) {

	for {
		time.Sleep(interval)

		//max_age should be negative, e.g. -1m
		cleanupCutoff := time.Now().Add(maxAge)
		for key, item := range *conntable {
			if item.inserted.Before(cleanupCutoff) {
				log.Debug("conntable GC("+strconv.Itoa(threadNum)+"): cleanup query ID " + strconv.Itoa(int(key)))
				delete(*conntable, key)
			}
		}
	}
}

func handleDns(conntable *map[uint16]dnsMapEntry, dns layers.DNS, logC chan dnsLogEntry,
	srcIP net.IP, dstIP net.IP) {
	//skip non-query stuff (Updates, AXFRs, etc)
	if dns.OpCode != layers.DNSOpCodeQuery {
		log.Debug("Saw non-query DNS packet")
	}

	//other checks should go here.


	//pre-allocated for initLogEntry
	logs := []dnsLogEntry{}

	//lookup the query ID in our connection table
	item, foundItem := (*conntable)[dns.ID]

	//this is a Query Response packet and we saw the question go out...
	//if we saw a leg of this already...
	if foundItem {
		//do I need this?
		logs = nil
		//if we just got the reply 
		if dns.QR {
			log.Debug("Got 'answer' leg of query ID: " + strconv.Itoa(int(dns.ID)))
			initLogEntry(srcIP, dstIP, item.entry, dns, &logs)
		} else {
			//we just got the question, so we should already have the reply
			log.Debug("Got the 'question' leg of query ID " + strconv.Itoa(int(dns.ID)))
			initLogEntry(srcIP, dstIP, dns, item.entry, &logs)
		}
		delete(*conntable, dns.ID)
	
		//TODO: send the array itself, not the elements of the array
		//to reduce the number of channel transactions
		for _, logEntry := range logs {
			logC <- logEntry
		}
		
	}else{
		//This is the initial query.  save it for later.
		log.Debug("Got a leg of query ID " + strconv.Itoa(int(dns.ID)))
		mapEntry := dnsMapEntry{
			entry:    dns,
			inserted: time.Now(),
		}
		(*conntable)[dns.ID] = mapEntry
		
	}
}

/* validate if DNS packet, make conntable entry and output
   to log channel if there is a match
   
   we pass packet by value here because we turned on ZeroCopy for the capture, which reuses the capture buffer
*/
func handlePacket(packets chan packetData, logC chan dnsLogEntry,
	gcInterval time.Duration, gcAge time.Duration, threadNum int) {

	//DNS IDs are stored as uint16s by the gopacket DNS layer
	var conntable = make(map[uint16]dnsMapEntry)

	//setup garbage collection for this map
	go cleanDnsCache(&conntable, gcAge, gcInterval, threadNum)

	var ethLayer layers.Ethernet
    var ipLayer  layers.IPv4
    var udpLayer layers.UDP
    var tcpLayer layers.TCP
    var dns layers.DNS
    var payload gopacket.Payload
	
	//we're constraining the set of layer decoders that gopacket will apply
	//to this traffic. this MASSIVELY speeds up the parsing phase
	parser := gopacket.NewDecodingLayerParser(
            layers.LayerTypeEthernet,
            &ethLayer,
            &ipLayer,
            &udpLayer,
            &tcpLayer,
            &dns,
            &payload,
        )
	
	//for parsing the reassembled TCP streams
	dnsParser := gopacket.NewDecodingLayerParser(
            layers.LayerTypeDNS,
            &dns,
            &payload,
        )
	
	foundLayerTypes := []gopacket.LayerType{}

	//TCP reassembly init
	streamFactory := &dnsStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	ticker := time.Tick(time.Minute)

	for{
		select{
			case packet, more := <- packets:
		
				//used for clean shutdowns
				if !more {
					return
				}else if packet.Type == "flush" {
					count:=assembler.FlushAll()
					log.Debug("(thread "+strconv.Itoa(threadNum)+") flushed "+strconv.Itoa(count)+" connections")
					continue
				}
				
				//we're intentionally ignoring the errors that DecodeLayers will
				//return if it can't parse an entire packet.  We check the list of
				//discovered layers to work through a couple of possible error states.
				
				var srcIP net.IP
				var dstIP net.IP
				
				if packet.Type == "packet" {
					parser.DecodeLayers(packet.Packet.Data(), &foundLayerTypes)
					srcIP = ipLayer.SrcIP 
					dstIP = ipLayer.DstIP
				}else if packet.Type == "tcp" {
					if len(packet.Tcpdata.DnsData) != packet.Tcpdata.Length {
						log.Debugf("Got TCP data of length %d, expecting %d", len(packet.Tcpdata.DnsData), packet.Tcpdata.Length)
					}
					dnsParser.DecodeLayers(packet.Tcpdata.DnsData, &foundLayerTypes)
					srcIP = net.IP(packet.Tcpdata.IpLayer.Src().Raw())
					dstIP = net.IP(packet.Tcpdata.IpLayer.Dst().Raw())
				}else{
					log.Debug("Got a channel entry with no data!")
					continue
				}
				
				//All TCP goes to reassemble.  This is first because a single packet DNS request will parse as DNS
				//But that will leave the connection hanging around in memory, because the inital handshake won't
				//parse as DNS, nor will the connection closing.
				if foundLayerType(layers.LayerTypeTCP, foundLayerTypes) {
					assembler.AssembleWithTimestamp(ipLayer.NetworkFlow(), &tcpLayer, packet.Packet.Metadata().Timestamp)
					continue
				}else if foundLayerType(layers.LayerTypeDNS, foundLayerTypes){
					handleDns(&conntable, dns, logC, srcIP, dstIP)
				}else{
					//UDP and doesn't parse as DNS?
					log.Debug("Missing a DNS layer?")
				}
			case <-ticker:
				// Every minute, flush connections that haven't seen activity in the past 2 minutes.
				assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
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
/*	} else if dev != "" && pfring {
		handle, err = pfring.NewRing(dev, 65536, true, pfring.FlagPromisc)
		if err != nil {
			log.Debug(err)
			return nil
		}
*/
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
	
/*	if dev != "" && pfring {
		handle.Enable()
	}
*/

	return handle
}

//kick off packet procesing threads and start the packet capture loop
func doCapture(handle *pcap.Handle, logChan chan dnsLogEntry,
	gcAge string, gcInterval string, numprocs int, reChan chan tcpDataStruct) {

	gcAgeDur, err := time.ParseDuration(gcAge)

	if err != nil {
		log.Fatal("Your gc_age parameter was not parseable.  Use a string like '-1m'")
	}

	gcIntervalDur, err := time.ParseDuration(gcInterval)

	if err != nil {
		log.Fatal("Your gc_age parameter was not parseable.  Use a string like '3m'")
	}

	//setup the global channel for reassembled TCP streams
	reassembleChan = reChan

	/* init channels for the packet handlers and kick off handler threads */
	var channels []chan packetData
	for i := 0; i < numprocs; i++ {
		channels = append(channels, make(chan packetData, 100))
	}

	for i := 0; i < numprocs; i++ {
		go handlePacket(channels[i], logChan, gcIntervalDur, gcAgeDur, i)
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

	channelData := packetData{}

CAPTURE:
	for {
		select{
			case reassembledTcp := <- reChan:
				channelData.Tcpdata = reassembledTcp
				channelData.Type = "tcp"
				channels[int(reassembledTcp.IpLayer.FastHash()) & (numprocs-1)] <- channelData
			case packet := <- packetSource.Packets():
				if packet != nil{
					parser.DecodeLayers(packet.Data(), &foundLayerTypes)
					channelData.Packet = packet
					channelData.Type = "packet"
					if foundLayerType(layers.LayerTypeIPv4, foundLayerTypes) {
						channels[int(ipLayer.NetworkFlow().FastHash()) & (numprocs-1)] <- channelData
					}
				} else{ 
					log.Debug("packetSource returned nil.")
					break CAPTURE
				}
		}
	}

	gracefulShutdown(channels, reChan, logChan)

}
	
func gracefulShutdown(channels []chan packetData, reChan chan tcpDataStruct, logChan chan dnsLogEntry)	{

	var wait_time int = 3
	channelData := packetData{}
	var numprocs int = len(channels)
	
	log.Debug("Flushing channels...")
	for i := 0; i < numprocs; i++ {
		channels[i] <- packetData{Type:"flush"}
	}
	log.Debug("Draining TCP data...")
	
	OUTER:
	for {
		select{
			case reassembledTcp := <- reChan:
				channelData.Tcpdata = reassembledTcp
				channelData.Type = "tcp"
				channels[int(reassembledTcp.IpLayer.FastHash()) & (numprocs-1)] <- channelData
			case <- time.After(3*time.Second):
				break OUTER
		}
	}
	
	log.Debug("Stopping packet processing...")
	for i := 0; i < numprocs; i++ {
		close(channels[i])
	}
	
	log.Debug("waiting for log pipeline to flush...")
	close(logChan)
	
	for len(logChan) > 0 {
		wait_time--
		if wait_time == 0{
			log.Debug("exited with messages remaining in log queue!")
			return
		}
		time.Sleep(time.Second)
	}
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

	logOpts := NewLogOptions(*quiet, *debug, *logFile, *kafkaBrokers, *kafkaTopic)

	logChan := initLogging(logOpts)

	reChan := make(chan tcpDataStruct)

	//spin up logging thread(s)
	go logConn(logChan, logOpts)

	//spin up the actual capture threads
	doCapture(handle, logChan, *gcAge, *gcInterval, *numprocs, reChan)

	log.Debug("Done!  Goodbye.")
	os.Exit(0)

}
