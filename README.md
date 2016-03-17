
#TODO

   * multi-packet TCP questions and answers are ignored
   * several types are not defined, and so logged by number instead of name
   * several types don't log all information (e.g. MX records don't log priority)
   * no tests yet exist
   * logging to Kafka and general stats logging is not done
   * PF_RING integration exists but has not been tested
   * the use of the query ID as the key in the connection table may lead to collisions
   * test and fix (as needed) windows support

#gopassivedns
Network-based DNS logging in Go

##Summary
A network-capture based DNS logger, inspired by https://github.com/gamelinux/passivedns.  It uses gopacket to deal with libpcap and packet processing.  It outputs JSON logs.  It is intended to deal with high volume query capture in environments with anywhewre from one to hundreds of DNS resolvers.

###Why not use PassiveDNS from gamelinux?
It's a good choice.  I built this because I believe tasks like involving processing large amounts of untrusted data with lots of poorly documented corner cases should be handled by a managed runtime to prevent memory corruption-style attacks.

###Why not use Bro (or insert other DNS logging IDS here)?
Also a good choice.  Systems like Bro are generally deployed on network egresses, which has the consequence of masking the real source of the lookup behind your recursive resolvers.  This means you generally need to deploy Bro and do resolver query logging (assuming you can), and integrate logs from both of those into a central logging system to track a lookup back to a client.  gopassivedns was designed to be deployed on your resolvers with no resolver config changes and/or on your network egresses, log centrally via a reliable protocol and parse simply into any log system.  

###Why not just use resolver query logging?
Resolver support for query logging, including both the question and answer is spotty at best.  One of the most-deployed DNS servers, BIND, doesn't support it at all.  Others, like Windows DNS, have really horrible log formats.  Additionally, network-based logging will catch queries sent directly to remote servers (e.g. Google DNS) from your clients.

##Usage

   * -dev [device]              network device for capture
   * -bpf [bpf filter]          BPF filter for capture (default: port 53)
   * -pcap [file]               pcap file to process
   * -logfile [file]            log file for DNS lookups (suggested for small deployment or debugging only)
   * -quiet                     don't log DNS lookups to STDOUT
   * -debug                     enable debug logging to STDOUT
   * -gc_age [num]              age at which incomplete connections should be garbage collected (default: -1m)
   * -gc_interval [num]         interval at which GC should run on connection table (default: 3m)
   * -kafka_brokers [brokers]   comma-separated list of kafka brokers
   * -kafka_topic [topic]       kafka topic for logging
   * -cpuprofile [file]         enable CPU profiling
   * -numprocs [num]            number of goroutines to use for parsing packet data (default: 8)
   * -pfring                    use PF_RING for packet capture

You must supply either -dev or -pcap.  

There are known issues with goroutines and the standard daemonize process (https://github.com/golang/go/issues/227), so I strongly recommend you use one of the methods detaild here: http://stackoverflow.com/questions/10067295/how-to-start-a-go-program-as-a-daemon-in-ubuntu to run this process as a daemon using system tools.

##Deployment Guide

###Where do I deploy this?
You have 3 choices: deploy it on your resolver(s) or deploy it on your gateway(s) or both.  Deploying on your resolvers is good because you will get the IP address of the client that sent the origianl request.  You can also see the upstream leg of the request (from the resolver to the next resolver in the chain), unless you tune your BPF filter to ignore that leg.  Deploying on your gateways means you don't see the client -> internal resolver leg, so it can be hard to tie a request back to a specific client.  On the other hand, you'll see requests that bypass your internal resolvers.  You will also, of course, see the queries coming from the resolver to whatever upstream resolver it uses.  In an ideal world, I would deploy this tool on each of my internal resolvers and on a tap on my gateways.  The internal resolvers would have a BPF filter such that it ignores the upstream leg of the query, and the gateway would not ignore anything.

###What should I do with the results?
Right now, I'd recommend using logstash to ship the logs to an elasticsearch cluster.  All the logs are JSON, so this should be pretty easy.  In the future, I will add native kafka support that should make that easier.  I would also suggest using something like HDFS for long term storage and bulk analysis.  DNS queries are an amazing source of internal data!

##Build and install
   * clone this repo
   * install libpcap, libpcap-dev and PF_RING
   * 'go get'
   * 'go build -o gopassivedns'  (the -o is really just being careful, assuming you cloned the repo you shouldn't need it)
   * 'cp gopassivedns /some/path/to/gopassivedns'

