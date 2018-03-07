
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

   * -dev [device]              network device for capture (ENV: PDNS_DEV)
   * -fluentd_socket [socket]   Path to Fluentd unix socket used for logging in messagepack format (ENV: PDNS_FLUENTD_SOCKET)
   * -bpf [bpf filter]          BPF filter for capture (default: port 53) (ENV: PDNS_BPF)
   * -pcap [file]               pcap file to process (ENV: PDNS_PCAP_FILE)
   * -logfile [file]            log file for DNS lookups (suggested for small deployment or debugging only) (ENV: PDNS_LOG_FILE)
   * -logMaxAge                 max age of a log file before rotation, in days (default: 28) (ENV: PDNS_LOG_AGE)
   * -logMaxBackups             max number of files kept after rotation (default: 3) (ENV: PDNS_LOG_BACKUP)
   * -logMaxSize                max size of log file before rotation, in MB (default: 100) (ENV: PDNS_LOG_SIZE)
   * -quiet                     don't log DNS lookups to STDOUT (ENV: PDNS_QUIET)
   * -debug                     enable debug logging to STDOUT (ENV: PDNS_DEBUG)
   * -gc_age [num]              age at which incomplete connections should be garbage collected (default: -1m) (ENV: PDNS_GC_AGE)
   * -gc_interval [num]         interval at which GC should run on connection table (default: 3m) (ENV: PDNS_GC_INTERVAL)
   * -kafka_brokers [brokers]   comma-separated list of kafka brokers (ENV: PDNS_KAFKA_PEERS)
   * -kafka_topic [topic]       kafka topic for logging (ENV: PDNS_KAFKA_TOPIC)
   * -cpuprofile [file]         enable CPU profiling (ENV: PDNS_PROFILE_FILE)
   * -numprocs [num]            number of goroutines to use for parsing packet data (default: 8) (ENV: PDNS_THREADS)
   * -pfring                    use PF_RING for packet capture (ENV: PDNS_PFRING)
   * -statsd_host               host and port of your statsd server (e.g. localhost:8125) (ENV: PDNS_STATSD_HOST)
   * -statsd_interval           the interval, in seconds, between sends to statsd (ENV: PDNS_STATSD_INTERVAL)
   * -statsd_prefix             the metric name prefix to use (by default, gopassivedns) (ENV: PDNS_STATSD_PREFIX)
   * -snaplen [int]             the snaplen used for the pcap buffer
   * -name                      the name of this sensor for use in stats and log messages (defaults to hostname) (ENV: PDNS_NAME)
   * -syslog_facility           syslog facility (ENV: PDNS_SYSLOG_FACILITY)
   * -syslog_priority           syslog priority (ENV: PDNS_SYSLOG_PRIORITY)

You must supply either -dev or -pcap.  

There are known issues with goroutines and the standard daemonize process (https://github.com/golang/go/issues/227), so I strongly recommend you use one of the methods detaild here: http://stackoverflow.com/questions/10067295/how-to-start-a-go-program-as-a-daemon-in-ubuntu to run this process as a daemon using system tools.

If you choose to use syslog logging, we use golang's "log/syslog" which requires a unix socket used to communicate with syslog to be at one of /dev/log, /var/run/log or /var/run/syslog.

## Deployment Guide

### Where do I deploy this?
You have 3 choices: deploy it on your resolver(s) or deploy it on your gateway(s) or both.  Deploying on your resolvers is good because you will get the IP address of the client that sent the origianl request.  You can also see the upstream leg of the request (from the resolver to the next resolver in the chain), unless you tune your BPF filter to ignore that leg.  Deploying on your gateways means you don't see the client -> internal resolver leg, so it can be hard to tie a request back to a specific client.  On the other hand, you'll see requests that bypass your internal resolvers.  You will also, of course, see the queries coming from the resolver to whatever upstream resolver it uses.  In an ideal world, I would deploy this tool on each of my internal resolvers and on a tap on my gateways.  The internal resolvers would have a BPF filter such that it ignores the upstream leg of the query, and the gateway would not ignore anything.

### What should I do with the results?
Right now, I'd recommend using logstash to ship the logs to an elasticsearch cluster.  All the logs are JSON, so this should be pretty easy.  I would also suggest using something like HDFS for long term storage and bulk analysis.  DNS queries are an amazing source of internal data!

## Build and install
   * clone this repo
   * install libpcap, libpcap-dev
   * 'go get'
   * 'go build -o gopassivedns'  (the -o is really just being careful, assuming you cloned the repo you shouldn't need it)
   * 'cp gopassivedns /some/path/to/gopassivedns'

