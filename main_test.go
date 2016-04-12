package main

import "testing"
import log "github.com/Sirupsen/logrus"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"
import "time"
import "net"

func getPacketData(which string) *gopacket.PacketSource {
    var pcapFile string = "data/"+which+".pcap"

    handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Debug(err)
		return nil
	}
    
    return gopacket.NewPacketSource(handle, handle.LinkType())
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

//func handlePacket(packets chan gopacket.Packet, logC chan dnsLogEntry,
//	gcInterval time.Duration, gcAge time.Duration)

/*
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
*/

func TestParseA(t *testing.T){
    gcAge, _ := time.ParseDuration("-1m")
	gcInterval, _ := time.ParseDuration("3m")
    
    var packetChan = make(chan gopacket.Packet)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge)
    
    packetSource := getPacketData("a")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packet
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
    
    var packetChan = make(chan gopacket.Packet)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge)
    
    packetSource := getPacketData("aaaa")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packet
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
    
    var packetChan = make(chan gopacket.Packet)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge)
    
    packetSource := getPacketData("ns")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packet
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
    
    var packetChan = make(chan gopacket.Packet)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge)
    
    packetSource := getPacketData("mx")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packet
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

/*
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
    
    var packetChan = make(chan gopacket.Packet)
    var logChan = make(chan dnsLogEntry)

    go handlePacket(packetChan, logChan, gcInterval, gcAge)
    
    packetSource := getPacketData("mx")
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
	    packetChan <- packet
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

