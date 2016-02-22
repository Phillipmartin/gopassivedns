package main

import "flag"
import "fmt"
import "log"
import "strconv"
import "time"
import "net"
//import "os"
import "encoding/json"
//import "github.com/Shopify/sarama"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"


/*
    logging to file
    debug logging
    ttlcache for failed queries
    documentation
release v1    
    
    stats output
    perf testing
    TCP flow support
release v2

    logging to kafka
    add PF_RING support
release v3
    
    maybe use something with a larger keyspace than the query ID for the conntable map
    maybe not so many string conversions?
    maybe move the dnsLogEntry struct -> JSON encoding to the log channel?
    add more Types to gopacket
*/



/*

DNS log entry struct and helper functions

*/
type dnsLogEntry struct {
    Query_ID        uint16          `json:"query_id"`
    Response_Code   int             `json:"response_code"`
	Question        string          `json:"question"`
	Question_Type   string          `json:"question_type"`
	Answer          string          `json:"answer"`
	Answer_Type     string          `json:"answer_type"`
	TTL             uint32          `json:"ttl"`
	Server          net.IP          `json:"server"`
	Client          net.IP          `json:"client"`
	Timestamp       string          `json:"timestamp"`

	encoded []byte  //to hold the marshaled data structure
	err     error   //encoding errors
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

/* validate if DNS, make conntable entry and output 
   to log channel if there is a match 
   */
func handlePacket(packets chan gopacket.Packet, logC chan string){
    
    //DNS IDs are stored as uint16s by the gopacket DNS layer
    //TODO: fix the memory leak of failed lookups by making this a ttlcache
    var conntable = make(map[uint16]*layers.DNS)
    
    for packet := range packets {
        //TODO: there must be a better way of doing this with gopacket
        var srcIP net.IP
        var dstIP net.IP

        if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
            ipData, _ := ipLayer.(*layers.IPv4)
            srcIP = ipData.SrcIP
            dstIP = ipData.DstIP
        }else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
            ipData, _ := ipLayer.(*layers.IPv6)
            srcIP = ipData.SrcIP
            dstIP = ipData.DstIP
        }else{
            //non-IP transport?  Ignore this packet
            //TODO: debug message here
            continue
        }
        
        if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
            // Get actual DNS data from this layer
            dns, _ := dnsLayer.(*layers.DNS)
            
            //skip non-query stuff (Updates, AXFRs, etc)
            if dns.OpCode != layers.DNSOpCodeQuery {
                //TODO: debug message here "saw non query packet with ID NNNN"
                continue
            }
            
            //this is a Query Response packet
            if dns.QR == true{
                if question, ok := conntable[dns.ID]; ok != false {
                    //We have both legs of the connection, so drop the connection from the table
                    //TODO: debug message here "got second leg of query ID NNNN"
                    delete(conntable, question.ID)
                    
                    /*
                        http://forums.devshed.com/dns-36/dns-packet-question-section-1-a-183026.html
                        multiple questions isn't really a thing, so we'll loop over the answers and
                        insert the question section from the original query.  This means a successful
                        ANY query may result in a lot of seperate log entries.  The query ID will be
                        the same on all of those entries, however, so you can rebuild the query that
                        way.
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
                        case 255:   //ANY query per http://tools.ietf.org/html/rfc1035#page-12
                            questionType = "ANY"
                    }
                    
                    //a response code of 0 means success
                    if dns.ResponseCode != 0 {
                    
                        //TODO: debug message here "query failure code N for query ID NNNN"
                    
                        logEntry := &dnsLogEntry{
                            Query_ID:       dns.ID,
    		            	Question:       string(question.Questions[0].Name),
    		            	Response_Code:  int(dns.ResponseCode),
                			Question_Type:  questionType,
    			            Answer:         dns.ResponseCode.String(),
                			Answer_Type:    "",
    			            TTL:            0,
    			            //this is the answer packet, which comes from the server...
    			            Server:         srcIP,
    			            //...and goes to the client
    			            Client:         dstIP,
    			            Timestamp:      time.Now().UTC().Format(time.RFC3339),
                		}
                		
                		//marshal to JSON.  Maybe we should do this in the log thread?
                		encoded, _ := logEntry.Encode()
                        
                        logC <- string(encoded)
                        
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

                        logEntry := &dnsLogEntry{
                            Query_ID:       dns.ID,
    		            	Question:       string(question.Questions[0].Name),
    		            	Response_Code:  int(dns.ResponseCode),
                			Question_Type:  questionType,
    			            Answer:         answerString,
                			Answer_Type:    typeString,
    			            TTL:            answer.TTL,
    			            //this is the answer packet, which comes from the server...
    			            Server:         srcIP,
    			            //...and goes to the client
    			            Client:         dstIP,
    			            Timestamp:      time.Now().UTC().Format(time.RFC3339),
                		}
                		
                		//marshal to JSON.  Maybe we should do this in the log thread?
                		encoded, _ := logEntry.Encode()
                        
                        logC <- string(encoded)
                    }
                }else{
                    //This might happen if we get a query ID collision
                    //TODO: debug message here 
                    log.Println("got a Query Response and can't find a query!")
                    continue
                }
            }else{
                //This is the initial query.  save it for later.
                //TODO: debug message here "got first leg of query ID NNNN"
                conntable[dns.ID] = dns
            }
        }
    }
}

func logConn(logC chan string){
    for message := range logC {
        fmt.Println(message)
    }
}

func main(){

    var dev = flag.String("dev", "", "Capture Device")
//    var kafka_brokers   = flag.String("kafka_brokers", os.Getenv("KAFKA_PEERS"), "The Kafka brokers to connect to, as a comma separated list")
//    var kafka_topic = flag.String("kafka_topic","","Kafka topic for output")
    var bpf = flag.String("bpf","port 53","BPF Filter")
    var pcapFile = flag.String("pcap","","pcap file")
//    var logfile = flag.String("logfile","","log file (recommended for debug only")
    
    flag.Parse()
    
    var handle *pcap.Handle
    var err error
    
    if(*dev != ""){
        handle, err = pcap.OpenLive(*dev, 65536, true, pcap.BlockForever)
        if err != nil {log.Fatal(err) }
    }else if(*pcapFile != ""){
        handle, err = pcap.OpenOffline(*pcapFile)
        if err != nil { log.Fatal(err) }
    }else{
        log.Fatal("You must specify either a capture device or a pcap file")
    }
    
    defer handle.Close()
    
    err = handle.SetBPFFilter(*bpf)
    if err != nil { log.Fatal(err) }
 
    /* spin up logging thread */
    var logChan = make(chan string)
    go logConn(logChan)
 
    /* init channels for the packet handlers and kick off handler threads */
    var channels [8]chan gopacket.Packet
    for i := 0; i < 8; i++ {
        channels[i] = make(chan gopacket.Packet)
        go handlePacket(channels[i], logChan)
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
            channels[int(net.NetworkFlow().FastHash()) & 0x7] <- packet
        }
    }    
}
