package main

import "os"
import "strconv"
import "flag"
import log "github.com/Sirupsen/logrus"

type pdnsConfig struct {
	device string
	pcapFile string
	bpf string
	
	sensorName string
	debug bool
	cpuprofile string
	quiet bool
	gcAge string
	gcInterval string
	numprocs int
	pfring bool
	
	kafkaBrokers string
	kafkaTopic string
	logFile string
	statsdHost string
	statsdInterval int
	statsdPrefix string
}

func initConfig() *pdnsConfig {
    config := pdnsConfig{}

	var dev = flag.String("dev", getEnvStr("PDNS_DEV", ""), "Capture Device")
	var kafkaBrokers = flag.String("kafka_brokers", getEnvStr("PDNS_KAFKA_PEERS", ""), "The Kafka brokers to connect to, as a comma separated list")
	var kafkaTopic = flag.String("kafka_topic", getEnvStr("PDNS_KAFKA_TOPIC", ""), "Kafka topic for output")
	var bpf = flag.String("bpf", getEnvStr("PDNS_BPF", "port 53"), "BPF Filter")  //default port 53
	var pcapFile = flag.String("pcap", getEnvStr("PDNS_PCAP_FILE", ""), "pcap file")
	var logFile = flag.String("logfile", getEnvStr("PDNS_LOG_FILE", ""), "log file (recommended for debug only")
	var quiet = flag.Bool("quiet", getEnvBool("PDNS_QUIET", false), "do not log to stdout")
	var gcAge = flag.String("gc_age", getEnvStr("PDNS_GC_AGE", "-1m"), "How old a connection table entry should be before it is garbage collected.")  //-1m
	var gcInterval = flag.String("gc_interval", getEnvStr("PDNS_GC_INTERVAL", "3m"), "How often to run garbage collection.")  //3m
	var debug = flag.Bool("debug", getEnvBool("PDNS_DEBUG", false), "Enable debug logging") 
	var cpuprofile = flag.String("cpuprofile", getEnvStr("PDNS_PROFILE_FILE", ""), "write cpu profile to file") //""
	var numprocs = flag.Int("numprocs", getEnvInt("PDNS_THREADS", 8), "number of packet processing threads")  //8
	var pfring = flag.Bool("pfring", getEnvBool("PDNS_PFRING", false), "Capture using PF_RING")
	var sensorName = flag.String("name", getEnvStr("PDNS_NAME", ""), "sensor name used in logging and stats reporting")
	var statsdHost = flag.String("statsd_host", getEnvStr("PDNS_STATSD_HOST", ""), "Statsd server hostname or IP")
	var statsdInterval = flag.Int("statsd_interval", getEnvInt("PDNS_STATSD_INTERVAL", 3), "Seconds between metric flush") //3
	var statsdPrefix = flag.String("statsd_prefix", getEnvStr("PDNS_STATSD_PREFIX", "gopassivedns"), "statsd metric prefix")  //gopassivedns
	var configFile = flag.String("config", getEnvStr("PDNS_CONFIG", ""), "config file")

	flag.Parse()

	if *sensorName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			*sensorName = "UNKNOWN"
		} else {
			sensorName = &hostname
		}
	}

	//pack it all into that struct

	//if we get a config file, ignore everything else and load it
	if *configFile != "" {
		//load file
	}else{
		//pack the vars into the config struct
		config = pdnsConfig{
			device:			*dev,
			pcapFile:		*pcapFile,
			bpf:			*bpf,
			
			sensorName:		*sensorName,
			debug:			*debug,
			cpuprofile:		*cpuprofile,
			quiet:			*quiet,
			gcAge:			*gcAge,
			gcInterval:		*gcInterval,
			numprocs:		*numprocs,
			pfring:			*pfring,
			
			kafkaBrokers:	*kafkaBrokers,
			kafkaTopic:		*kafkaTopic,
			logFile:		*logFile,
			statsdHost:		*statsdHost,
			statsdInterval:	*statsdInterval,
			statsdPrefix:	*statsdPrefix,
		}
	}
	
	return &config
}

func getEnvStr(name string, def string) string {
	content, found := os.LookupEnv(name)
	if found {
		return content
	}else{
		return def
	}
}

func getEnvBool(name string, def bool) bool {
	content, found := os.LookupEnv(name)
	if found {
		parsed, err := strconv.ParseBool(content)
		if err == nil {
			return parsed
		}else{
			log.Debugf("Could not parse the content of %s, %s, as a bool", name, content)
			return def
		}
	}else{
		return def
	}
}

func getEnvInt(name string, def int) int {
	content, found := os.LookupEnv(name)
	if found {
		parsed,err := strconv.ParseInt(content, 0, 32)
		if err == nil {
			return int(parsed)
		}else{
			log.Debugf("Could not parse the content of %s, %s, as an int", name, content)
			return def
		}
	}else{
		return def
	}
}