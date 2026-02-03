package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/quipo/statsd"
	log "github.com/Sirupsen/logrus"
)

/*

Structs and helper functions

*/

/*
  struct for DNS connection table entry
  the 'inserted' value is used in connection table cleanup
*/
type dnsMapEntry struct {
	entry    layers.DNS
	inserted time.Time
}

/*
  struct for DNS connection table
*/
type connectionTable struct {
	connections map[string]dnsMapEntry
	sync.RWMutex
}

/*
  struct to store reassembled TCP streams
*/
type tcpDataStruct struct {
	DnsData []byte
	IpLayer gopacket.Flow
	Length  int
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

/*
  create constant for the packetQueue as this is used in multiple places.
*/
const packetQueue int = 500

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
			// Ensure the length of data is at least two for integer parsing,
			// skip to next iterator if too short
			if len(data) < 2 {
				return
			}
			// Parse the actual integer
			dns_data_len := int(binary.BigEndian.Uint16(data[:2]))
			// Ensure the length of data is the parsed size +2,
			// skip to next iterator if too short
			if len(data) < dns_data_len+2 {
				return
			}
			reassembleChan <- tcpDataStruct{
				DnsData: data[2 : dns_data_len+2],
				IpLayer: d.net,
				Length:  int(binary.BigEndian.Uint16(data[:2])),
			}
			return
		} else if err != nil {
			log.Debug("Error when reading DNS buf: ", err)
		} else if count > 0 {

			data = append(data, tmp...)

		}
	}
}

/*
	takes the src IP, dst IP, DNS question, DNS reply and the logs struct to populate.
	returns nothing, but populates the logs array
*/
func initLogEntry(
	syslogPriority string,
	srcIP net.IP,
	srcPort string,
	dstIP net.IP,
	length *int,
	protocol *string,
	question layers.DNS,
	reply layers.DNS,
	inserted time.Time,
	logs *[]dnsLogEntry) {

	/*
	   http://forums.devshed.com/dns-36/dns-packet-question-section-1-a-183026.html
	   multiple questions isn't really a thing, so we'll loop over the answers and
	   insert the question section from the original query.  This means a successful
	   ANY query may result in a lot of seperate log entries.  The query ID will be
	   the same on all of those entries, however, so you can rebuild the query that
	   way.

	   TODO: Also loop through Additional records in addition to Answers
	*/

	if *protocol == "packet" {
		*protocol = "udp"
	}

	// guard against empty Questions slice (can happen with malformed packets)
	if len(question.Questions) == 0 {
		log.Debug("Skipping DNS entry with no questions")
		return
	}

	// a response code other than 0 means failure of some kind
	if reply.ResponseCode != 0 {

		*logs = append(*logs, dnsLogEntry{
			Level:                syslogPriority,
			Query_ID:             reply.ID,
			Question:             string(question.Questions[0].Name),
			Response_Code:        int(reply.ResponseCode),
			Question_Type:        TypeString(question.Questions[0].Type),
			Answer:               reply.ResponseCode.String(),
			Answer_Type:          "",
			TTL:                  0,
			Authoritative_Answer: reply.AA,
			Recursion_Desired:    question.RD,
			Recursion_Available:  question.RA,

			//this is the answer packet, which comes from the server...
			Server: srcIP,
			//...and goes to the client
			Client:      dstIP,
			Timestamp:   time.Now().UTC().String(),
			Elapsed:     time.Now().Sub(inserted).Nanoseconds(),
			Client_Port: srcPort,
			Length:      *length,
			Proto:       *protocol,
			Truncated:   reply.TC,
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
				Client: dstIP,
				//Timestamp:            time.Now().UTC().Format(time.RFC3339Nano),
				Timestamp:            time.Now().UTC().String(),
				Elapsed:              time.Now().Sub(inserted).Nanoseconds(),
				Client_Port:          srcPort,
				Level:                syslogPriority,
				Authoritative_Answer: reply.AA,
				Recursion_Desired:    question.RD,
				Recursion_Available:  question.RA,
				Length:               *length,
				Proto:                *protocol,
				Truncated:            reply.TC,
			})
		}
	}
}

/*
	background task to clear out stale entries in the conntable
	takes a pointer to the conntable to clean, the maximum age of an entry and how often to run GC
*/
func cleanDnsCache(
	conntable *connectionTable,
	maxAge time.Duration,
	interval time.Duration,
	stats *statsd.StatsdBuffer) {

	for {
		time.Sleep(interval)

		//max_age should be negative, e.g. -1m
		cleanupCutoff := time.Now().Add(maxAge)

		// collect keys to delete under read lock
		var toDelete []string
		conntable.RLock()
		for key, item := range conntable.connections {
			if item.inserted.Before(cleanupCutoff) {
				toDelete = append(toDelete, key)
			}
		}
		conntable.RUnlock()

		// delete under write lock
		if len(toDelete) > 0 {
			conntable.Lock()
			for _, key := range toDelete {
				log.Debug("conntable GC: cleanup query ID " + key)
				delete(conntable.connections, key)
			}
			conntable.Unlock()
			if stats != nil {
				stats.Incr("cache_entries_dropped", int64(len(toDelete)))
			}
		}
	}
}

func handleDns(
	conntable *connectionTable,
	dns *layers.DNS,
	logC chan dnsLogEntry,
	syslogPriority string,
	srcIP net.IP,
	srcPort string,
	dstPort string,
	dstIP net.IP,
	length *int,
	protocol *string,
	packetTime time.Time,
	stats *statsd.StatsdBuffer) {
	//skip non-query stuff (Updates, AXFRs, etc)
	if dns.OpCode != layers.DNSOpCodeQuery {
		log.Debug("Saw non-query DNS packet")
	}

	//other checks should go here.

	//pre-allocated for initLogEntry
	logs := []dnsLogEntry{}
	// generate a more unique key for a conntable map to avoid hash key collisions as dns.ID is not very unique
	var uid string
	if dstPort == "53" {
		uid = fmt.Sprintf("%s->%s:%s", strconv.Itoa(int(dns.ID)), srcPort, dstPort)
	} else {
		uid = fmt.Sprintf("%s->%s:%s", strconv.Itoa(int(dns.ID)), dstPort, srcPort)
	}

	conntable.RLock()
	//lookup the query ID:source port in our connection table
	item, foundItem := conntable.connections[uid]
	//this is a Query Response packet and we saw the question go out...
	//if we saw a leg of this already...
	if foundItem {
		//do I need this?
		logs = nil
		//if we just got the reply
		if dns.QR {
			log.Debug("Got 'answer' leg of query ID: " + strconv.Itoa(int(dns.ID)))
			initLogEntry(syslogPriority, srcIP, srcPort, dstIP, length, protocol, item.entry, *dns, item.inserted, &logs)
		} else {
			//we just got the question, so we should already have the reply
			log.Debug("Got the 'question' leg of query ID " + strconv.Itoa(int(dns.ID)))
			initLogEntry(syslogPriority, srcIP, srcPort, dstIP, length, protocol, *dns, item.entry, item.inserted, &logs)
		}
		conntable.RUnlock()
		conntable.Lock()
		delete(conntable.connections, uid)
		conntable.Unlock()
		//TODO: send the array itself, not the elements of the array
		//to reduce the number of channel transactions
		for _, logEntry := range logs {
			logC <- logEntry
		}

	} else {
		//This is the initial query.  save it for later.
		log.Debug("Got a leg of query ID " + strconv.Itoa(int(dns.ID)))
		mapEntry := dnsMapEntry{
			entry:    *dns,
			inserted: packetTime,
		}
		conntable.RUnlock()
		conntable.Lock()
		conntable.connections[uid] = mapEntry
		conntable.Unlock()
	}
}

/* validate if DNS packet, make conntable entry and output
   to log channel if there is a match

   we pass packet by value here because we turned on ZeroCopy for the capture, which reuses the capture buffer
*/
func handlePacket(
	conntable *connectionTable,
	packets chan *packetData,
	logC chan dnsLogEntry,
	syslogPriority string,
	gcInterval time.Duration,
	gcAge time.Duration,
	threadNum int,
	stats *statsd.StatsdBuffer) {

	//TCP reassembly init
	streamFactory := &dnsStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet, more := <-packets:

			//used for clean shutdowns
			if !more {
				return
			}

			err := packet.Parse()

			if err != nil {
				log.Debugf("Error parsing packet: %s", err)
				continue
			}

			srcIP := packet.GetSrcIP()
			dstIP := packet.GetDstIP()

			var packetTime time.Time

			if packet.GetTimestamp() != nil {
				packetTime = *packet.GetTimestamp()
			} else {
				log.Debug("Adding wall time not packet time to message.")
				if stats != nil {
					stats.Incr(strconv.Itoa(threadNum)+".packet_wall_time", 1)
				}
				packetTime = time.Now()
			}

			//All TCP goes to reassemble.  This is first because a single packet DNS request will parse as DNS
			//But that will leave the connection hanging around in memory, because the inital handshake won't
			//parse as DNS, nor will the connection closing.

			if packet.IsTCPStream() {
				//TODO Make them real
				srcPort := "0"
				dstPort := "0"

				handleDns(conntable,
					packet.GetDNSLayer(),
					logC,
					syslogPriority,
					srcIP,
					srcPort,
					dstPort,
					dstIP,
					packet.GetSize(),
					packet.GetProto(),
					packetTime,
					stats)
			} else if packet.HasTCPLayer() {
				assembler.AssembleWithTimestamp(
					packet.GetIPLayer().NetworkFlow(),
					packet.GetTCPLayer(), *packet.GetTimestamp())
				continue
			} else if packet.HasDNSLayer() {
				// these are reversed because they are over the wire.
				srcPort := strconv.Itoa(int(packet.udpLayer.DstPort))
				dstPort := strconv.Itoa(int(packet.udpLayer.SrcPort))
				handleDns(conntable,
					packet.GetDNSLayer(),
					logC,
					syslogPriority,
					srcIP,
					srcPort,
					dstPort,
					dstIP,
					packet.GetSize(),
					packet.GetProto(),
					packetTime,
					stats)
				if stats != nil {
					stats.Incr(strconv.Itoa(threadNum)+".dns_lookups", 1)
				}
			} else {
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
func initHandle(config *pdnsConfig) *pcap.Handle {

	var handle *pcap.Handle
	var err error

	if config.device != "" && !config.pfring {
		handle, err = pcap.OpenLive(config.device, config.snapLen, true, pcap.BlockForever)
		if err != nil {
			log.Debug(err)
			return nil
		}
	} else if config.pcapFile != "" {
		handle, err = pcap.OpenOffline(config.pcapFile)
		if err != nil {
			log.Debug(err)
			return nil
		}
	} else {
		log.Debug("You must specify either a capture device or a pcap file")
		return nil
	}

	err = handle.SetBPFFilter(config.bpf)
	if err != nil {
		log.Debug(err)
		return nil
	}

	return handle
}

//kick off packet procesing threads and start the packet capture loop
func doCapture(
	handle *pcap.Handle,
	logChan chan dnsLogEntry,
	config *pdnsConfig,
	reChan chan tcpDataStruct,
	stats *statsd.StatsdBuffer,
	done chan bool) {

	gcAgeDur, err := time.ParseDuration(config.gcAge)

	if err != nil {
		log.Fatal("Your gc_age parameter was not parseable.  Use a string like '-1m'")
	}

	gcIntervalDur, err := time.ParseDuration(config.gcInterval)

	if err != nil {
		log.Fatal("Your gc_age parameter was not parseable.  Use a string like '3m'")
	}

	//setup the global channel for reassembled TCP streams
	reassembleChan = reChan

	/* init channels for the packet handlers and kick off handler threads */
	var channels []chan *packetData
	for i := 0; i < config.numprocs; i++ {
		log.Debugf("Creating packet processing channel %d", i)
		channels = append(channels, make(chan *packetData, packetQueue))
	}

	//DNS IDs are stored as uint16s by the gopacket DNS layer
	var conntable = connectionTable{
		connections: make(map[string]dnsMapEntry),
	}

	//setup garbage collection for this map
	go cleanDnsCache(&conntable, gcAgeDur, gcIntervalDur, stats)

	var packetWg sync.WaitGroup
	for i := 0; i < config.numprocs; i++ {
		log.Debugf("Starting packet processing thread %d", i)
		packetWg.Add(1)
		go func(idx int) {
			defer packetWg.Done()
			handlePacket(&conntable, channels[idx], logChan, config.syslogPriority, gcIntervalDur, gcAgeDur, idx, stats)
		}(i)
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
	var ipLayer layers.IPv4

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
	)

	foundLayerTypes := []gopacket.LayerType{}
	scheduled := time.NewTicker(time.Duration(config.statsdInterval) * time.Second)

CAPTURE:
	for {
		select {
		case reassembledTcp := <-reChan:
			pd := NewTcpData(reassembledTcp)
			channels[int(reassembledTcp.IpLayer.FastHash())&(config.numprocs-1)] <- pd
			if stats != nil {
				stats.Incr("reassembed_tcp", 1)
			}
		case packet := <-packetSource.Packets():
			if packet != nil {
				parser.DecodeLayers(packet.Data(), &foundLayerTypes)
				if foundLayerType(layers.LayerTypeIPv4, foundLayerTypes) {
					pd := NewPacketData(packet)
					channels[int(ipLayer.NetworkFlow().FastHash())&(config.numprocs-1)] <- pd
					if stats != nil {
						stats.Incr("packets", 1)
					}
				}
			} else {
				//if we get here, we're likely reading a pcap and we've finished
				//or, potentially, the physical device we've been reading from has been
				//downed.  Or something else crazy has gone wrong...so we break
				//out of the capture loop entirely.

				log.Debug("packetSource returned nil.")
				break CAPTURE
			}
		case <-scheduled.C:
			handleStats, err := handle.Stats()

			if err != nil {
				continue
			}

			log.Printf("Statistics received: %d, dropped: %d, interface dropped %d",
				handleStats.PacketsReceived,
				handleStats.PacketsDropped,
				handleStats.PacketsIfDropped,
			)
			if stats != nil {
				stats.Incr("packets_received", int64(handleStats.PacketsReceived))
				stats.Incr("packets_dropped", int64(handleStats.PacketsDropped))
				stats.Incr("packets_ifdropped", int64(handleStats.PacketsIfDropped))
			}
		case <-done:
			log.Printf("gopassivedns: doCapture cleanly exiting.")
			break CAPTURE
		}
	}
	gracefulShutdown(channels, reChan, logChan, &packetWg)
}

//If we shut down without doing this stuff, we will lose some of the packet data
//still in the processing pipeline.
func gracefulShutdown(channels []chan *packetData,
	reChan chan tcpDataStruct,
	logChan chan dnsLogEntry,
	packetWg *sync.WaitGroup) {

	var wait_time int = 6
	var numprocs int = len(channels)

	log.Debug("Draining TCP data...")

OUTER:
	for {
		select {
		case reassembledTcp := <-reChan:
			pd := NewTcpData(reassembledTcp)
			channels[int(reassembledTcp.IpLayer.FastHash())&(numprocs-1)] <- pd
		case <-time.After(6 * time.Second):
			break OUTER
		}
	}

	log.Debug("Stopping packet processing...")
	for i := 0; i < numprocs; i++ {
		close(channels[i])
	}

	// Wait for all packet processing goroutines to finish sending to logChan
	// before closing it, to avoid a send-on-closed-channel race.
	packetWg.Wait()

	log.Debug("waiting for log pipeline to flush...")
	close(logChan)

	for len(logChan) > 0 {
		wait_time--
		if wait_time == 0 {
			log.Debug("exited with messages remaining in log queue!")
			return
		}
		time.Sleep(time.Second)
	}
}

// handle a graceful exit so that we do not lose data when we restart the service.
func watchSignals(sig chan os.Signal, done chan bool) {
	for {
		select {
		case <-sig:
			log.Println("Caught signal about to cleanly exit.")
			done <- true
			// Sleeping 15 seconds while the gracefulshutdown function completes.
			time.Sleep(15 * time.Second)
			return
		}
	}
}

func main() {

	//insert the ENV as defaults here, then after the parse we add the true defaults if nothing has been set
	//also convert true/false strings to true/false types

	config := initConfig()

	if config.cpuprofile != "" {
		f, err := os.Create(config.cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("Could not start CPU Profile ", err)
		}

		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	var stats *statsd.StatsdBuffer = nil

	if config.statsdHost != "" {
		statsdclient := statsd.NewStatsdClient(config.statsdHost, fmt.Sprintf("%s.%s.", config.statsdPrefix, config.sensorName))
		err := statsdclient.CreateSocket()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		stats = statsd.NewStatsdBuffer(time.Duration(config.statsdInterval)*time.Second, statsdclient)
	}

	handle := initHandle(config)

	if handle == nil {
		log.Fatal("Could not initilize the capture.")
	}

	logOpts := NewLogOptions(config)

	logChan := initLogging(logOpts, config)

	reChan := make(chan tcpDataStruct)

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)

	go watchSignals(sigs, done)

	//spin up logging thread(s)
	go logConn(logChan, logOpts, stats)

	//spin up the actual capture threads
	doCapture(handle, logChan, config, reChan, stats, done)

	log.Debug("Done!  Goodbye.")
}
