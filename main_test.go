package main

import "testing"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"
import "os/user"
import "time"
import "net"

/*
Utility functions

*/
func getPacketData(which string) *gopacket.PacketSource {
    var pcapFile string = "data/"+which+".pcap"

    handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil
	}
    
    return gopacket.NewPacketSource(handle, handle.LinkType())
}

func getHandle(which string) *pcap.Handle {
    var pcapFile string = "data/"+which+".pcap"

    handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil
	}
	
	return handle
}

func getDNSLayers(which string) []*layers.DNS {
    
    var ret []*layers.DNS

    packetSource := getPacketData(which)
    
    for packet := range packetSource.Packets(){
        if packet.ApplicationLayer().LayerType() == layers.LayerTypeDNS {
            dnsLayer := packet.Layer(layers.LayerTypeDNS)
            dns, _ := dnsLayer.(*layers.DNS)  //go type coerceion
            ret = append(ret, dns)
        }
    }
    
    return ret

}

func ToSlice(c chan dnsLogEntry) []dnsLogEntry {
    s := make([]dnsLogEntry, 0)

    for{
        select{
            case i := <- c:
                s = append(s, i)
            case <-time.After(time.Second):
                return s
        }
    }    
}

func LogMirrorBg(source chan dnsLogEntry, target chan dnsLogEntry)  {
    for{
        select{
            case i := <- source:
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
    var dstIP net.IP = net.ParseIP("2.2.2.2")
    DNSlayers := getDNSLayers("a")
    logs := []dnsLogEntry{}
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        logs=nil
        initLogEntry(srcIP, dstIP, *DNSlayers[0], *DNSlayers[1], &logs)
    }
}

func BenchmarkLogMarshal(b *testing.B) {
    var srcIP net.IP = net.ParseIP("1.1.1.1")
    var dstIP net.IP = net.ParseIP("2.2.2.2")
    DNSlayers := getDNSLayers("a")
    logs := []dnsLogEntry{}
    
    logs=nil
    initLogEntry(srcIP, dstIP, *DNSlayers[0], *DNSlayers[1], &logs)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        logs[0].Encode()
        logs[0].encoded=nil //un-cache the marshaled data
    }
    
}

func BenchmarkDecodeToIP(b *testing.B) {
    var ethLayer layers.Ethernet
    var ipLayer  layers.IPv4
	
	parser := gopacket.NewDecodingLayerParser(
            layers.LayerTypeEthernet,
            &ethLayer,
            &ipLayer,
        )
	
	foundLayerTypes := []gopacket.LayerType{}
	packetSource := getPacketData("a")
	packetSource.DecodeOptions.Lazy = true
	packet := <- packetSource.Packets()
	
	b.ResetTimer()
    for i := 0; i < b.N; i++ {
        parser.DecodeLayers(packet.Data(), &foundLayerTypes)
    }
	
}

func BenchmarkDecodeToDNS(b *testing.B) {
    var ethLayer layers.Ethernet
    var ipLayer  layers.IPv4
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
	packet := <- packetSource.Packets()
	
	b.ResetTimer()
    for i := 0; i < b.N; i++ {
        parser.DecodeLayers(packet.Data(), &foundLayerTypes)
    }
	
}

func BenchmarkHandleUDPPackets(b *testing.B){
    gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")
    
    var packetChan = make(chan packetData, 101)
    var logChan = make(chan dnsLogEntry)

	go func (){for{<- logChan}}()
	
	b.ResetTimer()
    for i := 0; i < b.N; i++ {
        b.StopTimer()
        //print(".")
        packetSource := getPacketData("100_udp_lookups")
	    packetSource.DecodeOptions.Lazy = true
	    for packet := range packetSource.Packets() {
	        packetChan <- packetData{Packet: packet, Type: "packet"}
	    }
	    packetChan <- packetData{Type: "stop"}
	    
	    //print(".")
	    b.StartTimer()
	    handlePacket(packetChan, logChan, gcInterval, gcAge, 1)
    }

}

/*
Tests

*/

func TestParseA(t *testing.T){
    gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")
    
    var packetChan = make(chan packetData)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge, 1)
    
    packetSource := getPacketData("a")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packetData{Packet: packet, Type: "packet"}
	}

    select {
    case log := <-logChan:
    
        if len(logChan) > 0 {
            //if we have more than 1 log message, we miss-parsed
            t.Fatal("More than 1 log message was present in the channel\n")
        }
        
        //validate values of log struct
        if log.Query_ID != 0x4fb8 {
            t.Fatalf("Bad Query ID %d, expecting %d\n",log.Query_ID,0x4fb8)
        }
        
        if log.Response_Code != 0 {
            t.Fatalf("Bad Response code %d, expecting 0\n", log.Response_Code)
        }
        
        if log.Question != "www.slashdot.org"  {
            t.Fatalf("Bad question %s, expecting www.slashdot.org\n", log.Question)
        }
        
        if log.Question_Type != "A"  {
            t.Fatalf("Bad question type %s, expecting A\n", log.Question_Type)
        }
        
        if log.Answer != "216.34.181.48"  {
            t.Fatalf("Bad answer %s, expecting 216.34.181.48\n", log.Answer)
        }
        
        if log.Answer_Type != "A"  {
            t.Fatalf("Bad answer type %s, expecting A\n", log.Answer_Type)
        }
        
        if log.TTL != 110  {
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



func TestParseAAAA(t *testing.T){
    gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")
    
    var packetChan = make(chan packetData)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge, 1)
    
    packetSource := getPacketData("aaaa")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packetData{Packet: packet, Type: "packet"}
	}

    select {
    case log := <-logChan:
    
        if len(logChan) > 0 {
            //if we have more than 1 log message, we miss-parsed
            t.Fatal("More than 1 log message was present in the channel\n")
        }
        
        //validate values of log struct
        if log.Query_ID != 0x1a63 {
            t.Fatalf("Bad Query ID %d, expecting %d\n",log.Query_ID,0x1a63)
        }
        
        if log.Response_Code != 0 {
            t.Fatalf("Bad Response code %d, expecting 0\n", log.Response_Code)
        }
        
        if log.Question != "www.google.com"  {
            t.Fatalf("Bad question %s, expecting www.google.com\n", log.Question)
        }
        
        if log.Question_Type != "AAAA"  {
            t.Fatalf("Bad question type %s, expecting AAAA\n", log.Question_Type)
        }
        
        if log.Answer != "2607:f8b0:4001:c02::93"  {
            t.Fatalf("Bad answer %s, expecting 2607:f8b0:4001:c02::93\n", log.Answer)
        }
        
        if log.Answer_Type != "AAAA"  {
            t.Fatalf("Bad answer type %s, expecting AAAA\n", log.Answer_Type)
        }
        
        if log.TTL != 55  {
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


func TestParseNS(t *testing.T){
    gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")
    
    var packetChan = make(chan packetData)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge, 1)
    
    packetSource := getPacketData("ns")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packetData{Packet: packet, Type: "packet"}
	}

    select {
    case log := <-logChan:
    
        if len(logChan) > 3 {
            //if we have more than 3 log messages (4 total), we miss-parsed
            t.Fatal("More than 4 log messages were present in the channel\n")
        }
        
        //validate values of log struct
        if log.Query_ID != 0x6162 {
            t.Fatalf("Bad Query ID %d, expecting %d\n",log.Query_ID,0x6162)
        }
        
        if log.Response_Code != 0 {
            t.Fatalf("Bad Response code %d, expecting 0\n", log.Response_Code)
        }
        
        if log.Question != "google.com"  {
            t.Fatalf("Bad question %s, expecting google.com\n", log.Question)
        }
        
        if log.Question_Type != "NS"  {
            t.Fatalf("Bad question type %s, expecting NS\n", log.Question_Type)
        }
        
        if log.Answer != "ns2.google.com"  {
            t.Fatalf("Bad answer %s, expecting ns2.google.com\n", log.Answer)
        }
        
        if log.Answer_Type != "NS"  {
            t.Fatalf("Bad answer type %s, expecting NS\n", log.Answer_Type)
        }
        
        if log.TTL != 21581  {
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


func TestParseMX(t *testing.T){
    gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")
    
    var packetChan = make(chan packetData)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge, 1)
    
    packetSource := getPacketData("mx")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packetData{Packet: packet, Type: "packet"}
	}

    select {
    case log := <-logChan:
    
        if len(logChan) > 4 {
            //if we have more than 4 log messages (5 total), we miss-parsed
            t.Fatal("More than 4 log messages were present in the channel\n")
        }
        
        //validate values of log struct
        if log.Query_ID != 0x6f87 {
            t.Fatalf("Bad Query ID %d, expecting %d\n",log.Query_ID,0x6f87)
        }
        
        if log.Response_Code != 0 {
            t.Fatalf("Bad Response code %d, expecting 0\n", log.Response_Code)
        }
        
        if log.Question != "google.com"  {
            t.Fatalf("Bad question %s, expecting google.com\n", log.Question)
        }
        
        if log.Question_Type != "MX"  {
            t.Fatalf("Bad question type %s, expecting MX\n", log.Question_Type)
        }
        
        if log.Answer != "alt3.aspmx.l.google.com"  {
            t.Fatalf("Bad answer %s, expecting alt3.aspmx.l.google.com\n", log.Answer)
        }
        
        if log.Answer_Type != "MX"  {
            t.Fatalf("Bad answer type %s, expecting MX\n", log.Answer_Type)
        }
        
        if log.TTL != 567  {
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

func TestParseNXDOMAIN(t *testing.T){
    gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")
    
    var packetChan = make(chan packetData)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge, 1)
    
    packetSource := getPacketData("nxdomain")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packetData{Packet: packet, Type: "packet"}
	}

    logs := ToSlice(logChan)
    
    if len(logs) > 1{
        t.Fatalf("Expecting a single log, got %d", len(logs))
    }
    
    log := logs[0]
    

    //validate values of log struct
    if log.Query_ID != 0xb369 {
        t.Fatalf("Bad Query ID %d, expecting %d\n",log.Query_ID,0xb369)
    }
    
    if log.Response_Code != 3 {
        t.Fatalf("Bad Response code %d, expecting 3\n", log.Response_Code)
    }
    
    if log.Question != "asdtartfgeasf.asdfgsdf.com"  {
        t.Fatalf("Bad question %s, expecting asdtartfgeasf.asdfgsdf.com\n", log.Question)
    }
    
    if log.Question_Type != "A"  {
        t.Fatalf("Bad question type %s, expecting A\n", log.Question_Type)
    }
    
    if log.Answer != "Non-Existent Domain"  {
        t.Fatalf("Bad answer %s, expecting Non-Existent Domain\n", log.Answer)
    }
    
    if log.Answer_Type != ""  {
        t.Fatalf("Bad answer type %s, expecting an empty string\n", log.Answer_Type)
    }
    
    if log.TTL != 0  {
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

func TestParseMultipleUDPPackets(t *testing.T){
    gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")
    
     //if I don't specify 6 here, this test stalls putting packets into the channel.
     //so strange.
    var packetChan = make(chan packetData, 6)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge, 1)
    
    packetSource := getPacketData("multiple_udp")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packetData{Packet: packet, Type: "packet"}
	}
	
	logs := ToSlice(logChan)

	if len(logs) != 3 {
            //if we have more than 3 log messages, we miss-parsed
            t.Fatalf("There were %d log messages, expecting 3", len(logs))
        }
        
        //validate values of log struct
        if logs[2].Query_ID != 0xb967 {
            t.Fatalf("Bad Query ID %d, expecting %d\n",logs[2].Query_ID,0x6f87)
        }
        
        if logs[2].Response_Code != 0 {
            t.Fatalf("Bad Response code %d, expecting 0\n", logs[2].Response_Code)
        }
        
        if logs[2].Question != "www.fark.com"  {
            t.Fatalf("Bad question %s, expecting google.com\n", logs[2].Question)
        }
        
        if logs[2].Question_Type != "A"  {
            t.Fatalf("Bad question type %s, expecting MX\n", logs[2].Question_Type)
        }
        
        if logs[2].Answer != "64.191.171.200"  {
            t.Fatalf("Bad answer %s, expecting alt3.aspmx.l.google.com\n", logs[2].Answer)
        }
        
        if logs[2].Answer_Type != "A"  {
            t.Fatalf("Bad answer type %s, expecting MX\n", logs[2].Answer_Type)
        }
        
        if logs[2].TTL != 600  {
            t.Fatalf("Bad TTL %d, expecting 567", logs[2].TTL)
        }
	
}


/*
doCapture(handle *pcap.Handle, logChan chan dnsLogEntry,
	gcAge string, gcInterval string, numprocs int) {
*/

func TestDoCaptureUDP(t *testing.T){
    
    handle := getHandle("100_udp_lookups")
    var logChan = make(chan dnsLogEntry, 100)
    var reChan = make(chan tcpDataStruct)
    var logStash = make(chan dnsLogEntry, 100)
    
    go LogMirrorBg(logChan, logStash)
    
    doCapture(handle, logChan, "-1m", "3m", 8, reChan)
    
    logs := ToSlice(logStash)
    
    if len(logs) != 50 {
        t.Fatalf("Expecting 50 logs, got %d", len(logs))
    }

}

func TestDoCaptureTCP(t *testing.T){
    
    handle := getHandle("100_tcp_lookups")
    var logChan = make(chan dnsLogEntry, 400)
    var reChan = make(chan tcpDataStruct, 1000)
    var logStash = make(chan dnsLogEntry, 400)

    go LogMirrorBg(logChan, logStash)
    
    doCapture(handle, logChan, "-1m", "3m", 8, reChan)
    
    logs := ToSlice(logStash)
    
    if len(logs) != 300 {
        t.Fatalf("Expecting 300 logs, got %d", len(logs))
    }

}

/*

func TestDoCaptureMixed(*testing.T){
    
}


func TestParseMultipleTCPPackets(*testing.T){

}

func TestParseSRV(*testing.T){
    
}

func TestParsePTR(*testing.T){
    
}

func TestParseANY(*testing.T){
    
}

func TestParseCNAME(*testing.T){
    
}

func TestParseSOA(*testing.T){
    
}

func TestParseUnknown(*testing.T){
    
}
*/

func TestConntableGC(t *testing.T){
    gcAge, _ := time.ParseDuration("-5s")
	gcInterval, _ := time.ParseDuration("5s")
    
    var packetChan = make(chan packetData)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge, 1)
    
    packetSource := getPacketData("mx")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packetData{Packet: packet, Type: "packet"}
	    time.Sleep(time.Duration(11)*time.Second)
	}
	
	select {
    case <-logChan:
        t.Fatal("Recieved a log message when expecting none!")
    case <-time.After(time.Second):
        break
    } 
}

/*
func TestTcpNoPayload(*testing.T){
    
}

func TestUDPNoPayload(*testing.T){
    
}

func TestTCPNotDNS(*testing.T){
    
}

func TestUDPNotDNS(*testing.T){
    
}

func TestTCPMultiPakcet(*testing.T){
    
}

*/

//func initHandle(dev string, pcapFile string, bpf string, pfring bool) *pcap.Handle

func TestInitHandlePcap(t *testing.T){
    handle := initHandle("", "data/a.pcap", "port 53", false)
    if handle == nil {
        t.Fatal("Error while building handle for data/a.pcap!")
    }
    handle.Close()
}

func TestInitHandlePcapFail(t *testing.T){
    handle := initHandle("", "data/doesnotexist.pcap", "port 53", false)
    if handle != nil {
        t.Fatal("initHandle did not error when given an invalid pcap")
    }
}

func TestInitHandleFail(t *testing.T){
    handle := initHandle("", "", "port 53", false)
    if handle != nil {
        t.Fatal("initHandle did not error out without a dev or a pcap!")
    }
}

func TestInitHandleBadBPF(t *testing.T){
    handle := initHandle("", "data/a.pcap", "asdf", false)
    if handle != nil {
        t.Fatal("initHandle did not fail with an invalid BPF filter")
    }
}

func TestInitHandleDev(t *testing.T){
    
    if u, err := user.Current();  err != nil || u.Username != "root" {
        t.Skip("We're not root, so we can't open devices for capture")
    }
    
    devices, err := pcap.FindAllDevs()
    if err != nil {
        t.Log(err)
        return
    }

    t.Log(devices)
    
    for _, device := range devices {
        handle := initHandle(device.Name, "", "port 53", false)
        if handle == nil {
            t.Logf("Error while building handle for %s", device.Name)
        }
    }
}

/*
func TestInitLogging(t *testing.T){

}
*/




