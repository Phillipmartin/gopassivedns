
[![Coverage Status](https://coveralls.io/repos/github/Phillipmartin/gopassivedns/badge.svg?branch=master)](https://coveralls.io/github/Phillipmartin/gopassivedns?branch=master)
[![Build Status](https://travis-ci.org/Phillipmartin/gopassivedns.svg?branch=master)](https://travis-ci.org/Phillipmartin/gopassivedns)
[![codebeat badge](https://codebeat.co/badges/14054f87-dca5-4ee1-a4ac-49266fa04019)](https://codebeat.co/projects/github-com-phillipmartin-gopassivedns)

# gopassivedns
Network-based DNS logging in Go

## Summary
A network-capture based DNS logger, inspired by https://github.com/gamelinux/passivedns.  It uses gopacket to deal with libpcap and packet processing.  It outputs JSON logs.  It is intended to deal with high volume query capture in environments with anywhewre from one to hundreds of DNS resolvers.

### Why not use PassiveDNS from gamelinux?
It's a good choice.  I built this because I believe tasks like involving processing large amounts of untrusted data with lots of poorly documented corner cases should be handled by a managed runtime to prevent memory corruption-style attacks.  I have deployed PassiveDNS in several orgs, and I built gopassivedns to solve a few specific pain points I observed: I needed to insturment a lot of locations, a needed to scale the storage layer to handle a LOT of lookups and I wanted a test suite with good coverage around all the DNS edge cases.

### Why not use Bro (or insert other DNS logging IDS here)?
Also a good choice.  Systems like Bro are generally deployed on network egresses, which has the consequence of masking the real source of the lookup behind your recursive resolvers.  This means you generally need to deploy Bro and do resolver query logging (assuming you can), and integrate logs from both of those into a central logging system to track a lookup back to a client.  gopassivedns was designed to be deployed on your resolvers with no resolver config changes and/or on your network egresses, log centrally via a reliable protocol and parse simply into any log system.  

### Why not just use resolver query logging?
Resolver support for query logging, including both the question and answer is spotty at best.  One of the most-deployed DNS servers, BIND, doesn't support it at all.  Others, like Windows DNS, have really horrible log formats.  Additionally, network-based logging will catch queries sent directly to remote servers (e.g. Google DNS) from your clients.

## Usage
Configuration options can be specified as environment variables, in a .env file on on the command line.  The priority is command line flags, .env file, and finally variables already defined in the environment.  Configuration options are as below

   * -assembly_debug_log 	            If true, the github.com/google/gopacket/tcpassembly library will log verbose debugging information (at least one line per packet)
   * -assembly_memuse_log               If true, the github.com/google/gopacket/tcpassembly library will log information regarding its memory use every once in a while.
   * -bpf [bpf filter]                  BPF Filter (default "port 53") (ENV: PDNS_BPF)
   * -config [filename]        	        Config file
   * -cpuprofile [filename]    	        Write cpu profile to file (ENV: PDNS_PROFILE_FILE)
   * -debug                 	        Enable debug logging (ENV: PDNS_DEBUG)
   * -dev [network interface]  	        Capture Device (ENV: PDNS_DEV)
   * -fluentd_socket [unix socket]      Path to Fluentd unix socket (ENV: PDNS_FLUENTD_SOCKET)
   * -gc_age [go time.Duration]    	    How old a connection table entry should be before it is garbage collected. (default "-1m") (ENV: PDNS_GC_AGE)
   * -gc_interval [go time.Duration]  	How often to run garbage collection. (default "3m") (ENV: PDNS_GC_INTERVAL)
   * -kafka_brokers [brokers]       	The Kafka brokers to connect to, as a comma separated list (ENV: PDNS_KAFKA_PEERS)
   * -kafka_topic [topic]               Kafka topic for output (ENV: PDNS_KAFKA_TOPIC)
   * -logMaxAge [int]                  	Max age of a log file before rotation, in days (default 28) (ENV: PDNS_LOG_AGE)
   * -logMaxBackups [int]           	Max number of files kept after rotation (default 3) (ENV: PDNS_LOG_BACKUP)
   * -logMaxSize [int]                  Max size of log file before rotation, in MB (default 100) (ENV: PDNS_LOG_SIZE)
   * -logfile [filename]            	Log file (recommended for debug only (ENV: PDNS_LOG_FILE)
   * -name [sensor name]            	Sensor name used in logging and stats reporting (ENV: PDNS_NAME)
   * -numprocs [goroutines]             Number of packet processing threads (default 8) (ENV: PDNS_THREADS)
   * -pcap [filename]                   PCAP file (ENV: PDNS_PCAP_FILE)
   * -quiet                             Do not log to stdout (ENV: PDNS_QUIET)
   * -snaplen [snaplen]                 The snaplen used in the pcap handle (default 4096)
   * -statsd_host [hostname]        	Statsd server hostname or IP (ENV: PDNS_STATSD_HOST)
   * -statsd_interval [flush interval]  Seconds between metric flush (default 5) (ENV: PDNS_STATSD_INTERVAL)
   * -statsd_prefix [metric prefix]     Statsd metric prefix (default "gopassivedns") (ENV: PDNS_STATSD_PREFIX)
   * -syslog_facility [facility]        Syslog facility (ENV: PDNS_SYSLOG_FACILITY)
   * -syslog_priority [priority]        Syslog priority (ENV: PDNS_SYSLOG_PRIORITY)

You must supply either -dev or -pcap.  

There are known issues with goroutines and the standard daemonize process (https://github.com/golang/go/issues/227), so I strongly recommend you use one of the methods detaild here: http://stackoverflow.com/questions/10067295/how-to-start-a-go-program-as-a-daemon-in-ubuntu to run this process as a daemon using system tools.

If you choose to use syslog logging, we use golang's "log/syslog" which requires a unix socket used to communicate with syslog to be at one of /dev/log, /var/run/log or /var/run/syslog.

## Deployment Guide

### Where do I deploy this?
You have 3 choices: deploy it on your resolver(s) or deploy it on your gateway(s) or both.  Deploying on your resolvers is good because you will get the IP address of the client that sent the origianl request.  You can also see the upstream leg of the request (from the resolver to the next resolver in the chain), unless you tune your BPF filter to ignore that leg.  Deploying on your gateways means you don't see the client -> internal resolver leg, so it can be hard to tie a request back to a specific client.  On the other hand, you'll see requests that bypass your internal resolvers.  You will also, of course, see the queries coming from the resolver to whatever upstream resolver it uses.  In an ideal world, I would deploy this tool on each of my internal resolvers and on a tap on my gateways.  The internal resolvers would have a BPF filter such that it ignores the upstream leg of the query, and the gateway would not ignore anything.

### What should I do with the results?
Right now, I'd recommend using logstash to ship the logs to an elasticsearch cluster.  All the logs are JSON, so this should be pretty easy.  I would also suggest using something like HDFS for long term storage and bulk analysis.  DNS queries are an amazing source of internal data!

## Build and install

Requires **[Glide](https://github.com/Masterminds/glide)** to manage the vendored dependencies. The glide update command in the following list will download and install the dependencies with the correct versions into the vendor folder to ensure a safe compile.

   * clone this repo
   * install libpcap, libpcap-dev
   * ```glide update```
   * ```go build -o gopassivedns```  (the -o is really just being careful, assuming you cloned the repo you shouldn't need it)
   * ```cp gopassivedns /some/path/to/gopassivedns```

