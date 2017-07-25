package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strconv"
)

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

func foundLayerType(layer gopacket.LayerType, found []gopacket.LayerType) bool {
	for _, value := range found {
		if value == layer {
			return true
		}
	}

	return false
}
