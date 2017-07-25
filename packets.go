package main

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

/*
  struct to store either reassembled TCP streams or packets
  Type will be tcp or packet for those type
  or it can be 'flush' or 'stop' to signal packet handling threads
*/
// codebeat:disable[TOO_MANY_IVARS]
type packetData struct {
	packet   gopacket.Packet
	tcpdata  tcpDataStruct
	datatype string

	foundLayerTypes []gopacket.LayerType

	ethLayer *layers.Ethernet
	ipLayer  *layers.IPv4
	udpLayer *layers.UDP
	tcpLayer *layers.TCP
	dns      *layers.DNS
	payload  *gopacket.Payload
}

// codebeat:enable[TOO_MANY_IVARS]

func NewTcpData(tcpdata tcpDataStruct) *packetData {
	var pd packetData
	pd.datatype = "tcp"
	pd.tcpdata = tcpdata
	return &pd
}

func NewPacketData(packet gopacket.Packet) *packetData {
	var pd packetData
	pd.datatype = "packet"
	pd.packet = packet
	return &pd
}

func (pd *packetData) Parse() error {

	if pd.datatype == "tcp" {
		pd.dns = &layers.DNS{}
		pd.payload = &gopacket.Payload{}
		//for parsing the reassembled TCP streams
		dnsParser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeDNS,
			pd.dns,
			pd.payload,
		)

		dnsParser.DecodeLayers(pd.tcpdata.DnsData, &pd.foundLayerTypes)

		return nil
	} else if pd.datatype == "packet" {
		pd.ethLayer = &layers.Ethernet{}
		pd.ipLayer = &layers.IPv4{}
		pd.udpLayer = &layers.UDP{}
		pd.tcpLayer = &layers.TCP{}
		pd.dns = &layers.DNS{}
		pd.payload = &gopacket.Payload{}
		//we're constraining the set of layer decoders that gopacket will apply
		//to this traffic. this MASSIVELY speeds up the parsing phase
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			pd.ethLayer,
			pd.ipLayer,
			pd.udpLayer,
			pd.tcpLayer,
			pd.dns,
			pd.payload,
		)

		parser.DecodeLayers(pd.packet.Data(), &pd.foundLayerTypes)

		return nil

	} else {
		return errors.New("Bad packet type: " + pd.datatype)
	}
}

func (pd *packetData) GetSrcIP() net.IP {
	if pd.ipLayer != nil {
		return pd.ipLayer.SrcIP
	} else {
		return net.IP(pd.tcpdata.IpLayer.Src().Raw())
	}

}

func (pd *packetData) GetDstIP() net.IP {
	if pd.ipLayer != nil {
		return pd.ipLayer.DstIP
	} else {
		return net.IP(pd.tcpdata.IpLayer.Dst().Raw())
	}
}

func (pd *packetData) IsTCPStream() bool {
	return pd.datatype == "tcp"
}

func (pd *packetData) GetTCPLayer() *layers.TCP {
	return pd.tcpLayer
}

func (pd *packetData) GetIPLayer() *layers.IPv4 {
	return pd.ipLayer
}

func (pd *packetData) GetDNSLayer() *layers.DNS {
	return pd.dns
}

func (pd *packetData) HasTCPLayer() bool {
	return foundLayerType(layers.LayerTypeTCP, pd.foundLayerTypes)
}

func (pd *packetData) HasIPLayer() bool {
	return foundLayerType(layers.LayerTypeIPv4, pd.foundLayerTypes)
}

func (pd *packetData) HasDNSLayer() bool {
	return foundLayerType(layers.LayerTypeDNS, pd.foundLayerTypes)
}

func (pd *packetData) GetTimestamp() *time.Time {
	if pd.datatype == "packet" {
		return &pd.packet.Metadata().Timestamp
	} else {
		return nil
	}
}
