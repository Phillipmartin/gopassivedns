# gopassivedns
Network-based DNS logging in Go

##Summary

a network-capture-based DNS logger, inspired by https://github.com/gamelinux/passivedns.  It uses gopacket to deal with libpcap and packet processing.  It outputs JSON logs.  It is intended to deal with high volume query capture in environments with anywhewre from one to hundreds of DNS resolvers.  Future development work will add a native kafka output channel (in addition to file logging).     

###Why not just use resolver query logging?
Resolver support for query logging, including both the question and answer is spotty at best.  One of the most-deployed DNS servers, BIND, doesn't support it at all.  Others, like Windows DNS, have really horrible log formats.  Additionally, network-based logging will catch queries sent directly to remote servers (e.g. Google DNS) from your clients.

##Usage

   * -i dev
   * -b bpf filter
   * -p pcap file
   * -l log file

You must supply either -i or -p.

##Deployment Guide

###Where do I deploy this?
You have 3 choices: deploy it on your resolver(s) or deploy it on your gateway(s) or both.  Deploying on your resolvers is good because you will get the IP address of the client that sent the origianl request.  You can also see the upstream leg of the request (from the resolver to the next resolver in the chain), unless you tune your BPF filter to ignore that leg.  Deploying on your gateways means you don't see the client -> internal resolver leg, so it can be hard to tie a request back to a specific client.  On the other hand, you'll see requests that bypass your internal resolvers.  You will also, of course, see the queries coming from the resolver to whatever upstream resolver it uses.  In an ideal world, I would deploy this tool on each of my internal resolvers and on a tap on my gateways.  The internal resolvers would have a BPF filter such that it ignores the upstream leg of the query, and the gateway would not ignore anything.

###What should I do with the results?
Right now, I'd recommend using logstash to ship the logs to an elasticsearch cluster.  All the logs are JSON, so this should be pretty easy.  In the future, I will add native kafka support that should make that easier.  I would also suggest using something like HDFS for long term storage and bulk analysis.  DNS queries are an amazing source of internal data!




