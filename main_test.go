package main

import (
	"flag"
	"log/syslog"
	"net"
	"os"
	"os/user"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/quipo/statsd"
)

var stats *statsd.StatsdBuffer = nil

/*
Utility functions

*/
func getPacketData(which string) *gopacket.PacketSource {
	var pcapFile string = "data/" + which + ".pcap"

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil
	}

	return gopacket.NewPacketSource(handle, handle.LinkType())
}

func getHandle(which string) *pcap.Handle {
	var pcapFile string = "data/" + which + ".pcap"

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil
	}

	return handle
}

func getDNSLayers(which string) []*layers.DNS {

	var ret []*layers.DNS

	packetSource := getPacketData(which)

	for packet := range packetSource.Packets() {
		if packet.ApplicationLayer().LayerType() == layers.LayerTypeDNS {
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			dns, _ := dnsLayer.(*layers.DNS) //go type coerceion
			ret = append(ret, dns)
		}
	}

	return ret

}

func ToSlice(c chan dnsLogEntry) []dnsLogEntry {
	s := make([]dnsLogEntry, 0)

	for {
		select {
		case i := <-c:
			s = append(s, i)
		case <-time.After(time.Second):
			return s
		}
	}
}

func LogMirrorBg(source chan dnsLogEntry, target chan dnsLogEntry) {
	for {
		select {
		case i := <-source:
			target <- i
		case <-time.After(time.Second):
			return
		}
	}
}

/*
Benchmarking functions

*/

func BenchmarkALogEntry(b *testing.B) {
	var srcIP net.IP = net.ParseIP("1.1.1.1")
	var srcPort string = "53100"
	var dstIP net.IP = net.ParseIP("2.2.2.2")
	var syslogPriority string = "DEBUG"
	var logProtocol string = "TCP"
	var length int = 141

	DNSlayers := getDNSLayers("a")
	logs := []dnsLogEntry{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logs = nil
		initLogEntry(syslogPriority, srcIP, srcPort, dstIP, &length, &logProtocol, *DNSlayers[0], *DNSlayers[1], time.Now(), &logs)
	}
}

func BenchmarkLogMarshal(b *testing.B) {
	var srcIP net.IP = net.ParseIP("1.1.1.1")
	var srcPort string = "53100"
	var dstIP net.IP = net.ParseIP("2.2.2.2")
	var syslogPriority string = "DEBUG"
	var logProtocol string = "TCP"
	var length int = 141

	DNSlayers := getDNSLayers("a")
	logs := []dnsLogEntry{}

	logs = nil
	initLogEntry(syslogPriority, srcIP, srcPort, dstIP, &length, &logProtocol, *DNSlayers[0], *DNSlayers[1], time.Now(), &logs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logs[0].Encode()
		logs[0].encoded = nil //un-cache the marshaled data
	}

}

func BenchmarkDecodeToIP(b *testing.B) {
	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
	)

	foundLayerTypes := []gopacket.LayerType{}
	packetSource := getPacketData("a")
	packetSource.DecodeOptions.Lazy = true
	packet := <-packetSource.Packets()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.DecodeLayers(packet.Data(), &foundLayerTypes)
	}

}

func BenchmarkDecodeToDNS(b *testing.B) {
	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4
	var udpLayer layers.UDP
	var tcpLayer layers.TCP
	var dns layers.DNS
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&udpLayer,
		&tcpLayer,
		&dns,
		&payload,
	)

	foundLayerTypes := []gopacket.LayerType{}
	packetSource := getPacketData("a")
	packetSource.DecodeOptions.Lazy = true
	packet := <-packetSource.Packets()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.DecodeLayers(packet.Data(), &foundLayerTypes)
	}

}

func BenchmarkHandleUDPPackets(b *testing.B) {
	gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")

	var syslogPriority string = "DEBUG"
	var logChan = make(chan dnsLogEntry)

	go func() {
		for {
			<-logChan
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		//print(".")
		var packetChan = make(chan *packetData, 101)
		packetSource := getPacketData("100_udp_lookups")
		packetSource.DecodeOptions.Lazy = true
		for packet := range packetSource.Packets() {
			packetChan <- NewPacketData(packet)
		}
		close(packetChan)

		//print(".")
		b.StartTimer()
		var conntable = connectionTable{
			connections: make(map[string]dnsMapEntry),
		}
		handlePacket(&conntable, packetChan, logChan, syslogPriority, gcInterval, gcAge, 1, stats)
	}

}

/*
Tests

*/

func TestDefaultConfig(t *testing.T) {
	os.Setenv("PDNS_DEV", "aaa")
	os.Setenv("PDNS_KAFKA_PEERS", "bbb")
	os.Setenv("PDNS_KAFKA_TOPIC", "ccc")
	os.Setenv("PDNS_BPF", "ddd")
	os.Setenv("PDNS_PCAP_FILE", "eee")
	os.Setenv("PDNS_LOG_FILE", "fff")
	os.Setenv("PDNS_LOG_AGE", "111")
	//os.Setenv("PDNS_LOG_BACKUP", "222")
	//os.Setenv("PDNS_LOG_SIZE", "333")
	//os.Setenv("PDNS_QUIET", "true")
	//os.Setenv("PDNS_GC_AGE", "kkk")
	//os.Setenv("PDNS_GC_INTERVAL", "aaa")
	os.Setenv("PDNS_DEBUG", "asdf")
	os.Setenv("PDNS_PROFILE_FILE", "ggg")
	os.Setenv("PDNS_THREADS", "aaa")
	os.Setenv("PDNS_PFRING", "true")
	//os.Setenv("PDNS_NAME", "hhh")
	os.Setenv("PDNS_STATSD_HOST", "iii")
	os.Setenv("PDNS_STATSD_INTERVAL", "777")
	os.Setenv("PDNS_STATSD_PREFIX", "jjj")
	//os.Setenv("PDNS_CONFIG", "")

	config := initConfig()

	if config.device != "aaa" {
		t.Fatal("")
	}

	if config.kafkaBrokers != "bbb" {
		t.Fatal("")
	}

	if config.kafkaTopic != "ccc" {
		t.Fatal("")
	}

	if config.bpf != "ddd" {
		t.Fatal("")
	}

	if config.pcapFile != "eee" {
		t.Fatal("")
	}

	if config.logFile != "fff" {
		t.Fatal("")
	}

	if config.logMaxAge != 111 {
		t.Fatal("")
	}

	if config.logMaxBackups != 3 {
		t.Fatal("")
	}

	if config.logMaxSize != 100 {
		t.Fatal("")
	}

	if config.quiet != false {
		t.Fatal("")
	}

	if config.gcAge != "-1m" {
		t.Fatal("")
	}

	if config.gcInterval != "3m" {
		t.Fatal("")
	}

	if config.debug != false {
		t.Fatal("")
	}

	if config.cpuprofile != "ggg" {
		t.Fatal("")
	}

	if config.numprocs != 8 {
		t.Fatal("")
	}

	if config.pfring != true {
		t.Fatal("")
	}

	hostname, err := os.Hostname()
	if err != nil {
		if config.sensorName != "UNKNOWN" {
			t.Fatalf("%s != %s", config.sensorName, "UNKNOWN")
		}
	} else {
		if config.sensorName != hostname {
			t.Fatalf("%s != %s", config.sensorName, hostname)
		}
	}

	if config.statsdHost != "iii" {
		t.Fatal("")
	}

	if config.statsdInterval != 777 {
		t.Fatal("")
	}

	if config.statsdPrefix != "jjj" {
		t.Fatal("")
	}

	if config.fluentdSocket != "" {
		t.Fatal("")
	}

	if config.snapLen != 4096 {
		t.Fatal("")
	}

	os.Unsetenv("PDNS_DEV")
	os.Unsetenv("PDNS_KAFKA_PEERS")
	os.Unsetenv("PDNS_KAFKA_TOPIC")
	os.Unsetenv("PDNS_BPF")
	os.Unsetenv("PDNS_PCAP_FILE")
	os.Unsetenv("PDNS_LOG_FILE")
	os.Unsetenv("PDNS_LOG_AGE")
	os.Unsetenv("PDNS_LOG_BACKUP")
	os.Unsetenv("PDNS_LOG_SIZE")
	os.Unsetenv("PDNS_QUIET")
	os.Unsetenv("PDNS_GC_AGE")
	os.Unsetenv("PDNS_GC_INTERVAL")
	os.Unsetenv("PDNS_DEBUG")
	os.Unsetenv("PDNS_PROFILE_FILE")
	os.Unsetenv("PDNS_THREADS")
	os.Unsetenv("PDNS_PFRING")
	os.Unsetenv("PDNS_NAME")
	os.Unsetenv("PDNS_STATSD_HOST")
	os.Unsetenv("PDNS_STATSD_INTERVAL")
	os.Unsetenv("PDNS_STATSD_PREFIX")

}

func TestParseA(t *testing.T) {
	gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")

	var syslogPriority string = "DEBUG"
	var packetChan = make(chan *packetData)
	var logChan = make(chan dnsLogEntry)

	//Consume load
	var conntable = connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	go handlePacket(&conntable, packetChan, logChan, syslogPriority, gcInterval, gcAge, 1, stats)

	packetSource := getPacketData("a")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
		packetChan <- NewPacketData(packet)
	}

	select {
	case log := <-logChan:

		if len(logChan) > 0 {
			//if we have more than 1 log message, we miss-parsed
			t.Fatal("More than 1 log message was present in the channel\n")
		}

		//validate values of log struct
		if log.Query_ID != 0x4fb8 {
			t.Fatalf("Bad Query ID %d, expecting %d\n", log.Query_ID, 0x4fb8)
		}

		if log.Response_Code != 0 {
			t.Fatalf("Bad Response code %d, expecting 0\n", log.Response_Code)
		}

		if log.Question != "www.slashdot.org" {
			t.Fatalf("Bad question %s, expecting www.slashdot.org\n", log.Question)
		}

		if log.Question_Type != "A" {
			t.Fatalf("Bad question type %s, expecting A\n", log.Question_Type)
		}

		if log.Answer != "216.34.181.48" {
			t.Fatalf("Bad answer %s, expecting 216.34.181.48\n", log.Answer)
		}

		if log.Answer_Type != "A" {
			t.Fatalf("Bad answer type %s, expecting A\n", log.Answer_Type)
		}

		if log.TTL != 110 {
			t.Fatalf("Bad TTL %d, expecting 110", log.TTL)
		}

		/*        if log.Server !=  {
		              t.Fatal("")
		          }

		          if log.Client !=  {
		              t.Fatal("")
		          }*/

		//parse the JSON and make sure it works
		log.Encode()
		if log.encoded == nil || log.err != nil {
			t.Fatal("log marshaling error!")
		}

	case <-time.After(time.Second):
		t.Fatal("No log messages were recieved")
	}

}

func TestParseAAAA(t *testing.T) {
	gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")

	var syslogPriority string = "DEBUG"
	var packetChan = make(chan *packetData)
	var logChan = make(chan dnsLogEntry)
	var conntable = connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	go handlePacket(&conntable, packetChan, logChan, syslogPriority, gcInterval, gcAge, 1, nil)

	packetSource := getPacketData("aaaa")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
		packetChan <- NewPacketData(packet)
	}

	select {
	case log := <-logChan:

		if len(logChan) > 0 {
			//if we have more than 1 log message, we miss-parsed
			t.Fatal("More than 1 log message was present in the channel\n")
		}

		//validate values of log struct
		if log.Query_ID != 0x1a63 {
			t.Fatalf("Bad Query ID %d, expecting %d\n", log.Query_ID, 0x1a63)
		}

		if log.Response_Code != 0 {
			t.Fatalf("Bad Response code %d, expecting 0\n", log.Response_Code)
		}

		if log.Question != "www.google.com" {
			t.Fatalf("Bad question %s, expecting www.google.com\n", log.Question)
		}

		if log.Question_Type != "AAAA" {
			t.Fatalf("Bad question type %s, expecting AAAA\n", log.Question_Type)
		}

		if log.Answer != "2607:f8b0:4001:c02::93" {
			t.Fatalf("Bad answer %s, expecting 2607:f8b0:4001:c02::93\n", log.Answer)
		}

		if log.Answer_Type != "AAAA" {
			t.Fatalf("Bad answer type %s, expecting AAAA\n", log.Answer_Type)
		}

		if log.TTL != 55 {
			t.Fatalf("Bad TTL %d, expecting 110", log.TTL)
		}

		/*        if log.Server !=  {
		              t.Fatal("")
		          }

		          if log.Client !=  {
		              t.Fatal("")
		          }*/

		//parse the JSON and make sure it works
		log.Encode()
		if log.encoded == nil || log.err != nil {
			t.Fatal("log marshaling error!")
		}

	case <-time.After(time.Second):
		t.Fatal("No log messages were recieved")
	}

}

func TestParseNS(t *testing.T) {
	gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")

	var syslogPriority string = "DEBUG"
	var packetChan = make(chan *packetData)
	var logChan = make(chan dnsLogEntry)
	var conntable = connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	go handlePacket(&conntable, packetChan, logChan, syslogPriority, gcInterval, gcAge, 1, nil)

	packetSource := getPacketData("ns")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
		packetChan <- NewPacketData(packet)
	}

	select {
	case log := <-logChan:

		if len(logChan) > 3 {
			//if we have more than 3 log messages (4 total), we miss-parsed
			t.Fatal("More than 4 log messages were present in the channel\n")
		}

		//validate values of log struct
		if log.Query_ID != 0x6162 {
			t.Fatalf("Bad Query ID %d, expecting %d\n", log.Query_ID, 0x6162)
		}

		if log.Response_Code != 0 {
			t.Fatalf("Bad Response code %d, expecting 0\n", log.Response_Code)
		}

		if log.Question != "google.com" {
			t.Fatalf("Bad question %s, expecting google.com\n", log.Question)
		}

		if log.Question_Type != "NS" {
			t.Fatalf("Bad question type %s, expecting NS\n", log.Question_Type)
		}

		if log.Answer != "ns2.google.com" {
			t.Fatalf("Bad answer %s, expecting ns2.google.com\n", log.Answer)
		}

		if log.Answer_Type != "NS" {
			t.Fatalf("Bad answer type %s, expecting NS\n", log.Answer_Type)
		}

		if log.TTL != 21581 {
			t.Fatalf("Bad TTL %d, expecting 110", log.TTL)
		}

		/*        if log.Server !=  {
		              t.Fatal("")
		          }

		          if log.Client !=  {
		              t.Fatal("")
		          }*/

		//parse the JSON and make sure it works
		log.Encode()
		if log.encoded == nil || log.err != nil {
			t.Fatal("log marshaling error!")
		}

	case <-time.After(time.Second):
		t.Fatal("No log messages were recieved")
	}
}

func TestParseMX(t *testing.T) {
	gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")

	var syslogPriority string = "DEBUG"
	var packetChan = make(chan *packetData)
	var logChan = make(chan dnsLogEntry)

	var conntable = connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	go handlePacket(&conntable, packetChan, logChan, syslogPriority, gcInterval, gcAge, 1, nil)

	packetSource := getPacketData("mx")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
		packetChan <- NewPacketData(packet)
	}

	select {
	case log := <-logChan:

		if len(logChan) > 4 {
			//if we have more than 4 log messages (5 total), we miss-parsed
			t.Fatal("More than 4 log messages were present in the channel\n")
		}

		//validate values of log struct
		if log.Query_ID != 0x6f87 {
			t.Fatalf("Bad Query ID %d, expecting %d\n", log.Query_ID, 0x6f87)
		}

		if log.Response_Code != 0 {
			t.Fatalf("Bad Response code %d, expecting 0\n", log.Response_Code)
		}

		if log.Question != "google.com" {
			t.Fatalf("Bad question %s, expecting google.com\n", log.Question)
		}

		if log.Question_Type != "MX" {
			t.Fatalf("Bad question type %s, expecting MX\n", log.Question_Type)
		}

		if log.Answer != "40 alt3.aspmx.l.google.com" {
			t.Fatalf("Bad answer %s, expecting 40 alt3.aspmx.l.google.com\n", log.Answer)
		}

		if log.Answer_Type != "MX" {
			t.Fatalf("Bad answer type %s, expecting MX\n", log.Answer_Type)
		}

		if log.TTL != 567 {
			t.Fatalf("Bad TTL %d, expecting 567", log.TTL)
		}

		/*        if log.Server !=  {
		              t.Fatal("")
		          }

		          if log.Client !=  {
		              t.Fatal("")
		          }*/

		//parse the JSON and make sure it works
		log.Encode()
		if log.encoded == nil || log.err != nil {
			t.Fatal("log marshaling error!")
		}

	case <-time.After(time.Second):
		t.Fatal("No log messages were recieved")
	}
}

func TestParseNXDOMAIN(t *testing.T) {
	gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")

	var syslogPriority string = "DEBUG"
	var packetChan = make(chan *packetData)
	var logChan = make(chan dnsLogEntry)

	var conntable = connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	go handlePacket(&conntable, packetChan, logChan, syslogPriority, gcInterval, gcAge, 1, nil)

	packetSource := getPacketData("nxdomain")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
		packetChan <- NewPacketData(packet)
	}

	logs := ToSlice(logChan)

	if len(logs) > 1 {
		t.Fatalf("Expecting a single log, got %d", len(logs))
	}

	log := logs[0]

	//validate values of log struct
	if log.Query_ID != 0xb369 {
		t.Fatalf("Bad Query ID %d, expecting %d\n", log.Query_ID, 0xb369)
	}

	if log.Response_Code != 3 {
		t.Fatalf("Bad Response code %d, expecting 3\n", log.Response_Code)
	}

	if log.Question != "asdtartfgeasf.asdfgsdf.com" {
		t.Fatalf("Bad question %s, expecting asdtartfgeasf.asdfgsdf.com\n", log.Question)
	}

	if log.Question_Type != "A" {
		t.Fatalf("Bad question type %s, expecting A\n", log.Question_Type)
	}

	if log.Answer != "Non-Existent Domain" {
		t.Fatalf("Bad answer %s, expecting Non-Existent Domain\n", log.Answer)
	}

	if log.Answer_Type != "" {
		t.Fatalf("Bad answer type %s, expecting an empty string\n", log.Answer_Type)
	}

	if log.TTL != 0 {
		t.Fatalf("Bad TTL %d, expecting 0", log.TTL)
	}

	/*        if log.Server !=  {
	    t.Fatal("")
	}

	if log.Client !=  {
	    t.Fatal("")
	}*/

	//parse the JSON and make sure it works
	log.Encode()
	if log.encoded == nil || log.err != nil {
		t.Fatal("log marshaling error!")
	}
}

func TestParseMultipleUDPPackets(t *testing.T) {
	gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")

	//if I don't specify 6 here, this test stalls putting packets into the channel.
	//so strange.
	var packetChan = make(chan *packetData, 6)
	var logChan = make(chan dnsLogEntry)
	var syslogPriority string = "DEBUG"

	var conntable = connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	go handlePacket(&conntable, packetChan, logChan, syslogPriority, gcInterval, gcAge, 1, nil)

	packetSource := getPacketData("multiple_udp")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
		packetChan <- NewPacketData(packet)
	}

	logs := ToSlice(logChan)

	if len(logs) != 3 {
		//if we have more than 3 log messages, we miss-parsed
		t.Fatalf("There were %d log messages, expecting 3", len(logs))
	}

	//validate values of log struct
	if logs[2].Query_ID != 0xb967 {
		t.Fatalf("Bad Query ID %d, expecting %d\n", logs[2].Query_ID, 0x6f87)
	}

	if logs[2].Response_Code != 0 {
		t.Fatalf("Bad Response code %d, expecting 0\n", logs[2].Response_Code)
	}

	if logs[2].Question != "www.fark.com" {
		t.Fatalf("Bad question %s, expecting google.com\n", logs[2].Question)
	}

	if logs[2].Question_Type != "A" {
		t.Fatalf("Bad question type %s, expecting MX\n", logs[2].Question_Type)
	}

	if logs[2].Answer != "64.191.171.200" {
		t.Fatalf("Bad answer %s, expecting alt3.aspmx.l.google.com\n", logs[2].Answer)
	}

	if logs[2].Answer_Type != "A" {
		t.Fatalf("Bad answer type %s, expecting MX\n", logs[2].Answer_Type)
	}

	if logs[2].TTL != 600 {
		t.Fatalf("Bad TTL %d, expecting 567", logs[2].TTL)
	}

}

/*
doCapture(handle *pcap.Handle, logChan chan dnsLogEntry,
	gcAge string, gcInterval string, numprocs int) {
*/

func TestDoCaptureUDP(t *testing.T) {

	handle := getHandle("100_udp_lookups")
	var logChan = make(chan dnsLogEntry, 100)
	var reChan = make(chan tcpDataStruct)
	var logStash = make(chan dnsLogEntry, 100)
	var done = make(chan bool, 1)

	go LogMirrorBg(logChan, logStash)

	doCapture(handle, logChan, &pdnsConfig{gcAge: "-1m", gcInterval: "3m", numprocs: 8, statsdInterval: 3}, reChan, stats, done)

	logs := ToSlice(logStash)

	if len(logs) != 50 {
		t.Fatalf("Expecting 50 logs, got %d", len(logs))
	}

}

func TestDoCaptureTCP(t *testing.T) {

	handle := getHandle("100_tcp_lookups")
	var logChan = make(chan dnsLogEntry, 400)
	var reChan = make(chan tcpDataStruct, 1000)
	var logStash = make(chan dnsLogEntry, 400)
	var done = make(chan bool, 1)

	go LogMirrorBg(logChan, logStash)

	doCapture(handle, logChan, &pdnsConfig{gcAge: "-1m", gcInterval: "3m", numprocs: 8, statsdInterval: 3}, reChan, stats, done)

	logs := ToSlice(logStash)

	if len(logs) != 300 {
		t.Fatalf("Expecting 300 logs, got %d", len(logs))
	}

}


func TestConntableGC(t *testing.T) {
	gcAge, _ := time.ParseDuration("-5s")
	gcInterval, _ := time.ParseDuration("5s")

	var syslogPriority string = "DEBUG"
	var packetChan = make(chan *packetData)
	var logChan = make(chan dnsLogEntry)

	var conntable = connectionTable{
		connections: make(map[string]dnsMapEntry),
	}
	go cleanDnsCache(&conntable, gcAge, gcInterval, stats)
	go handlePacket(&conntable, packetChan, logChan, syslogPriority, gcInterval, gcAge, 1, stats)

	packetSource := getPacketData("mx")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
		packetChan <- NewPacketData(packet)
		time.Sleep(time.Duration(11) * time.Second)
	}

	select {
	case <-logChan:
		t.Fatal("Recieved a log message when expecting none!")
	case <-time.After(time.Second):
		break
	}
}


//func initHandle(dev string, pcapFile string, bpf string, pfring bool) *pcap.Handle

func TestInitHandlePcap(t *testing.T) {
	handle := initHandle(&pdnsConfig{device: "", pcapFile: "data/a.pcap", bpf: "port 53", pfring: false})
	if handle == nil {
		t.Fatal("Error while building handle for data/a.pcap!")
	}
	handle.Close()
}

func TestInitHandlePcapFail(t *testing.T) {
	handle := initHandle(&pdnsConfig{device: "", pcapFile: "data/doesnotexist.pcap", bpf: "port 53", pfring: false})
	if handle != nil {
		t.Fatal("initHandle did not error when given an invalid pcap")
	}
}

func TestInitHandleFail(t *testing.T) {
	handle := initHandle(&pdnsConfig{device: "", pcapFile: "", bpf: "port 53", pfring: false})
	if handle != nil {
		t.Fatal("initHandle did not error out without a dev or a pcap!")
	}
}

func TestInitHandleBadBPF(t *testing.T) {
	handle := initHandle(&pdnsConfig{device: "", pcapFile: "data/a.pcap", bpf: "asdf", pfring: false})
	if handle != nil {
		t.Fatal("initHandle did not fail with an invalid BPF filter")
	}
}

func TestInitHandleDev(t *testing.T) {

	if u, err := user.Current(); err != nil || u.Username != "root" {
		t.Skip("We're not root, so we can't open devices for capture")
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		t.Log(err)
		return
	}

	t.Log(devices)

	for _, device := range devices {
		handle := initHandle(&pdnsConfig{device: device.Name, pcapFile: "", bpf: "port 53", pfring: false})
		if handle == nil {
			t.Logf("Error while building handle for %s", device.Name)
		}
	}
}


func TestParseFacility(t *testing.T) {
	m := make(map[string]syslog.Priority)

	m["KERN"] = syslog.LOG_KERN
	m["USER"] = syslog.LOG_USER
	m["MAIL"] = syslog.LOG_MAIL
	m["DAEMON"] = syslog.LOG_DAEMON
	m["AUTH"] = syslog.LOG_AUTH
	m["SYSLOG"] = syslog.LOG_SYSLOG
	m["LPR"] = syslog.LOG_LPR
	m["NEWS"] = syslog.LOG_NEWS
	m["UUCP"] = syslog.LOG_UUCP
	m["CRON"] = syslog.LOG_CRON
	m["AUTHPRIV"] = syslog.LOG_AUTHPRIV
	m["FTP"] = syslog.LOG_FTP
	m["LOCAL0"] = syslog.LOG_LOCAL0
	m["LOCAL1"] = syslog.LOG_LOCAL1
	m["LOCAL2"] = syslog.LOG_LOCAL2
	m["LOCAL3"] = syslog.LOG_LOCAL3
	m["LOCAL4"] = syslog.LOG_LOCAL4
	m["LOCAL5"] = syslog.LOG_LOCAL5
	m["LOCAL6"] = syslog.LOG_LOCAL6
	m["LOCAL7"] = syslog.LOG_LOCAL7

	for k, v := range m {
		fac, err := facilityToType(k)
		if fac != v || err != nil {
			t.Fatalf("facility %s did not parse as a facility", k)
		}
	}

	fac, err := facilityToType("notafac")
	if fac != 0 || err == nil {
		t.Fatal("facility 'notafac' return an error")
	}

}

func TestParsePriority(t *testing.T) {
	m := make(map[string]syslog.Priority)

	m["EMERG"] = syslog.LOG_EMERG
	m["ALERT"] = syslog.LOG_ALERT
	m["CRIT"] = syslog.LOG_CRIT
	m["ERR"] = syslog.LOG_ERR
	m["WARNING"] = syslog.LOG_WARNING
	m["NOTICE"] = syslog.LOG_NOTICE
	m["INFO"] = syslog.LOG_INFO
	m["DEBUG"] = syslog.LOG_DEBUG

	for k, v := range m {
		fac, err := levelToType(k)
		if fac != v || err != nil {
			t.Fatalf("facility %s did not parse as a facility", k)
		}
	}

	fac, err := levelToType("notapri")
	if fac != 0 || err == nil {
		t.Fatal("facility 'notafac' return an error")
	}

}


func TestMain(m *testing.M) {
	var statsdHost = flag.String("test_statsd_host", "", "Statsd server hostname or IP")
	var statsdInterval = flag.Int("test_statsd_interval", 3, "Seconds between metric flush")
	var statsdPrefix = flag.String("test_statsd_prefix", "gopassivedns", "statsd metric prefix")

	flag.Parse()

	if *statsdHost != "" {
		statsdclient := statsd.NewStatsdClient(*statsdHost, *statsdPrefix)
		stats = statsd.NewStatsdBuffer(time.Duration(*statsdInterval)*time.Second, statsdclient)
	}

	os.Exit(m.Run())
}
