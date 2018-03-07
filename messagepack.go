package main

import (
	"github.com/vmihailenco/msgpack"
)

// logEntry is the same as dnsLog without some fields which are not required
// for fluentd outputs.
type logEntry struct {
	Query_ID             uint16 `msgpack:"query_id"`
	Response_Code        int    `msgpack:"rcode"`
	Question             string `msgpack:"q"`
	Question_Type        string `msgpack:"qtype"`
	Answer               string `msgpack:"a"`
	Answer_Type          string `msgpack:"atype"`
	TTL                  uint32 `msgpack:"ttl"`
	Server               string `msgpack:"dst"`
	Client               string `msgpack:"src"`
	Timestamp            string `msgpack:"tstamp"`
	Elapsed              int64  `msgpack:"elapsed"`
	Client_Port          string `msgpack:"sport"`
	Level                string `msgpack:"level,omitempty"` // syslog level omitted if empty
	Length               int    `msgpack:"bytes"`
	Proto                string `msgpack:"protocol"`
	Truncated            bool   `msgpack:"truncated"`
	Authoritative_Answer bool   `msgpack:"aa"`
	Recursion_Desired    bool   `msgpack:"rd"`
	Recursion_Available  bool   `msgpack:"ra"`
}

func (dle *dnsLogEntry) MarshalMsgpack() ([]byte, error) {
	return msgpack.Marshal(&logEntry{
		Query_ID:             dle.Query_ID,
		Response_Code:        dle.Response_Code,
		Question:             dle.Question,
		Question_Type:        dle.Question_Type,
		Answer:               dle.Answer,
		Answer_Type:          dle.Answer_Type,
		TTL:                  dle.TTL,
		Server:               dle.Server.String(),
		Client:               dle.Client.String(),
		Timestamp:            dle.Timestamp,
		Elapsed:              dle.Elapsed,
		Client_Port:          dle.Client_Port,
		Level:                dle.Level,
		Length:               dle.Length,
		Proto:                dle.Proto,
		Truncated:            dle.Truncated,
		Authoritative_Answer: dle.Authoritative_Answer,
		Recursion_Desired:    dle.Recursion_Desired,
		Recursion_Available:  dle.Recursion_Available,
	})
}

// Yet to be finished UnmarshalMsgpack method.
func (dle *dnsLogEntry) UnmarshalMsgpack(data []byte) error {
	tmp := &dnsLogEntry{}
	if err := msgpack.Unmarshal(data, &tmp); err != nil {
		return err
	}

	return nil
}
