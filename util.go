package main

import (
	"fmt"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypeMD:
		return "MD"
	case layers.DNSTypeMF:
		return "MF"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypeMB:
		return "MB"
	case layers.DNSTypeMG:
		return "MG"
	case layers.DNSTypeMR:
		return "MR"
	case layers.DNSTypeNULL:
		return "NULL"
	case layers.DNSTypeWKS:
		return "WKS"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeHINFO:
		return "HINFO"
	case layers.DNSTypeMINFO:
		return "MINFO"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeSRV:
		return "SRV"
	case layers.DNSTypeOPT:
		return "OPT"
	case layers.DNSTypeRRSIG:
		return "RRSIG"
	case layers.DNSTypeDNSKEY:
		return "DNSKEY"
	case layers.DNSTypeSVCB:
		return "SVCB"
	case layers.DNSTypeHTTPS:
		return "HTTPS"
	case layers.DNSTypeURI:
		return "URI"
	case 255:
		return "ANY"
	default:
		return strconv.Itoa(int(dnsType))
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
	case layers.DNSTypeA:
		return rr.IP.String()
	case layers.DNSTypeAAAA:
		return rr.IP.String()
	case layers.DNSTypeCNAME:
		return string(rr.CNAME)
	case layers.DNSTypeMX:
		return fmt.Sprintf("%d %s", rr.MX.Preference, string(rr.MX.Name))
	case layers.DNSTypeNS:
		return string(rr.NS)
	case layers.DNSTypePTR:
		return string(rr.PTR)
	case layers.DNSTypeTXT:
		return string(rr.TXT)
	case layers.DNSTypeSOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			string(rr.SOA.MName), string(rr.SOA.RName),
			rr.SOA.Serial, rr.SOA.Refresh, rr.SOA.Retry,
			rr.SOA.Expire, rr.SOA.Minimum)
	case layers.DNSTypeSRV:
		return fmt.Sprintf("%d %d %d %s",
			rr.SRV.Priority, rr.SRV.Weight, rr.SRV.Port, string(rr.SRV.Name))
	case layers.DNSTypeURI:
		return string(rr.Data)
	case layers.DNSTypeOPT:
		return string(rr.Data)
	default:
		return string(rr.Data)
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
