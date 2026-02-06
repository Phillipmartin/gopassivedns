# gopassivedns Architecture Review

## Summary

This document identifies architectural inefficiencies, best-practice gaps, potential bottlenecks, and reliability issues in the gopassivedns codebase, along with suggested fixes and testing strategies.

---

## 1. TCP Reassembly Buffer Overread

**File:** `main.go:123`
**Severity:** High (correctness bug)

```go
data = append(data, tmp...)
```

When `dnsStream.run()` reads from the TCP reassembly reader, it appends the *entire* 4096-byte `tmp` buffer regardless of how many bytes were actually read (`count`). This means uninitialized/stale buffer data gets appended for any read shorter than 4096 bytes.

**Fix:**
```go
data = append(data, tmp[:count]...)
```

**How to test:** Create a test PCAP with a TCP DNS response smaller than 4096 bytes. Compare the parsed DNS payload before and after the fix. The current code may produce valid results by accident (the length-prefix parsing truncates), but it wastes memory and could cause subtle issues with multiple DNS messages on the same TCP connection.

---

## 2. No IPv6 Support

**File:** `main.go:544-551`, `packets.go:26`
**Severity:** High (feature gap)

The packet capture loop's load-balancing parser only decodes `layers.Ethernet` and `layers.IPv4`. Any IPv6 DNS traffic (increasingly common) is silently dropped at line 568:

```go
if foundLayerType(layers.LayerTypeIPv4, foundLayerTypes) {
```

Similarly, `packetData.ipLayer` is hardcoded to `*layers.IPv4`.

**Fix:** Add `layers.IPv6` to the decoding layer parser and the `packetData` struct. The load balancer should hash on whichever IP layer is present. Add an `ip6Layer *layers.IPv6` field to `packetData` and update `GetSrcIP`/`GetDstIP` accordingly.

**How to test:** Capture DNS queries to an IPv6-only resolver (e.g., `dig @2001:4860:4860::8888 example.com`), feed the PCAP to gopassivedns, and verify log output is produced. Currently it will produce nothing.

---

## 3. Unbuffered Log Sink Channels Create Backpressure Bottleneck

**File:** `log.go:165-195`
**Severity:** High (performance bottleneck)

All per-sink channels (`stdoutChan`, `fileChan`, `kafkaChan`, `syslogChan`, `fluentdChan`) are created unbuffered:

```go
stdoutChan := make(chan dnsLogEntry)
```

The fan-out loop in `logConn()` sends to each sink sequentially:

```go
for _, logChan := range logs {
    logChan <- message
}
```

If *any* sink blocks (Kafka reconnecting, syslog slow, stdout pipe full), the entire fan-out blocks, which backs up the main `logC` channel, which backs up all packet processing workers. A single slow sink stalls everything.

**Fix:** Buffer each sink channel (e.g., 1000 entries) and add a non-blocking send with a drop counter:

```go
select {
case logChan <- message:
default:
    stats.Incr("log_dropped", 1)
    log.Debug("Dropping log entry due to slow sink")
}
```

Alternatively, use separate goroutines per-sink with independent buffered channels.

**How to test:** Set up a Kafka sink pointed at an unreachable broker, then send traffic. Measure whether stdout logging continues or freezes. With the fix, stdout should remain responsive.

---

## 4. RLock-to-Lock Upgrade Race in `handleDns`

**File:** `main.go:296-334`
**Severity:** Medium (correctness/race condition)

```go
conntable.RLock()
item, foundItem := conntable.connections[uid]
if foundItem {
    // ...
    conntable.RUnlock()
    conntable.Lock()
    delete(conntable.connections, uid)
    conntable.Unlock()
} else {
    conntable.RUnlock()
    conntable.Lock()
    conntable.connections[uid] = mapEntry
    conntable.Unlock()
}
```

Between `RUnlock()` and `Lock()`, another goroutine can modify the map. This creates a TOCTOU (time-of-check-time-of-use) race:
- Two goroutines could both find the same entry, both try to delete it, and both produce duplicate log entries.
- Two goroutines could both miss an entry, both try to insert, and one overwrites the other.

**Fix:** Use a single `Lock()` (write lock) for the entire check-and-modify operation. The read lock optimization only helps when there is a high ratio of reads to writes; in this case every lookup is followed by a write, so the RLock provides no benefit.

```go
conntable.Lock()
item, foundItem := conntable.connections[uid]
if foundItem {
    delete(conntable.connections, uid)
    conntable.Unlock()
    // process logs...
} else {
    conntable.connections[uid] = mapEntry
    conntable.Unlock()
}
```

**How to test:** Write a concurrent test that sends the same DNS query ID from multiple goroutines simultaneously. Check that exactly one log entry is produced per matched query-response pair, not duplicates.

---

## 5. `numprocs` Must Be Power of Two (Undocumented/Unenforced)

**File:** `main.go:561,570`
**Severity:** Medium (silent misconfiguration)

```go
channels[int(ipLayer.NetworkFlow().FastHash())&(config.numprocs-1)] <- pd
```

The bitwise AND (`& (numprocs-1)`) only correctly distributes across all channels when `numprocs` is a power of two. If a user passes `-numprocs 12`, channels 8-11 will never receive packets and 4 worker goroutines sit idle.

**Fix:** Either enforce power-of-two at startup or use modulo:

```go
channels[int(ipLayer.NetworkFlow().FastHash()) % config.numprocs] <- pd
```

Modulo is slightly slower than bitwise AND but negligibly so, and it's correct for any value.

**How to test:** Run with `-numprocs 3` and a large PCAP. Check StatsD per-thread counters — with the current code, channel 2 will receive zero packets if `FastHash` values have certain bit patterns. After the fix, all three should receive traffic.

---

## 6. Stale CI Configuration

**File:** `.travis.yml`
**Severity:** Medium (operational)

The CI tests against Go 1.5, 1.6, and 1.7, but `go.mod` declares `go 1.24.7`. These old versions cannot compile the codebase (modules, language features). Travis CI itself is largely deprecated.

**Fix:** Migrate to GitHub Actions. Test against Go 1.23 and 1.24 (the currently supported releases). Example:

```yaml
# .github/workflows/test.yml
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go: ['1.23', '1.24']
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '${{ matrix.go }}' }
      - run: sudo apt-get install -y libpcap-dev
      - run: go test -v -race -coverprofile=coverage.out ./...
```

**How to test:** Push to a branch and verify CI passes on both Go versions. Confirm the old Travis config can be removed.

---

## 7. Custom Kafka Client Is Fragile

**File:** `kafka.go`
**Severity:** Medium (reliability)

The custom Kafka producer:
- Only connects to one broker (the first reachable one), with no failover if that broker goes down.
- Always writes to partition 0 — no partitioning strategy.
- Sends one message per TCP write (no batching), which is extremely inefficient at scale.
- Uses Kafka API v0, which is deprecated in modern Kafka clusters.
- Doesn't read the produce response error code (line 112: "a successful read is good enough").
- CRC32 comment says "Castagnoli" but the implementation uses IEEE polynomial `0xEDB88320`, and the comment on line 227 contradicts itself.

**Fix:** Consider replacing with the `segmentio/kafka-go` library which is lighter than Sarama but production-grade. If keeping the custom client, at minimum:
- Implement message batching (collect N messages or flush every M ms).
- Parse the produce response to detect actual errors.
- Support broker failover (round-robin on send failure).
- Add partition selection (hash on question domain).

**How to test:**
- Benchmark current vs. batched throughput with a Kafka broker (e.g., via docker-compose).
- Test broker failover by killing one broker in a multi-broker setup.
- Verify error responses (produce to a non-existent topic) are logged, not silently swallowed.

---

## 8. Fluentd Socket Has No Reconnection

**File:** `log.go:318-344`
**Severity:** Medium (reliability)

If the fluentd Unix socket connection drops after initial connect, the next `conn.Write()` fails and the program calls `log.Fatalf(...)`, terminating the entire process. This is especially problematic in containerized environments where fluentd may restart.

**Fix:** Wrap the write in a reconnect loop:
```go
if _, err = conn.Write(encoded); err != nil {
    log.Errorf("Fluentd write failed: %s, reconnecting...", err)
    conn.Close()
    conn = fluentdSocket(opts.FluentdSocket)
    // retry write once
}
```

**How to test:** Start gopassivedns with fluentd output, restart the fluentd process, and verify gopassivedns reconnects rather than crashing.

---

## 9. Syslog and Stdout Ignore Encoding Errors

**File:** `log.go:220,312`
**Severity:** Low-Medium

```go
encoded, _ := message.Encode()  // error discarded
```

If JSON encoding fails (e.g., due to an unusual IP representation), the error is silently swallowed and garbled or empty data gets written.

**Fix:** Check the error and log/skip:
```go
encoded, err := message.Encode()
if err != nil {
    log.Errorf("Failed to encode log entry: %s", err)
    continue
}
```

**How to test:** Create a `dnsLogEntry` with a nil `Server` IP field and confirm the error is logged rather than producing `"dst":null"` or panicking.

---

## 10. `time.Now()` Called Twice Per Log Entry

**File:** `main.go:186-188`, `main.go:210-211`
**Severity:** Low (inaccuracy)

```go
Timestamp: time.Now().UTC().String(),
Elapsed:   time.Now().Sub(inserted).Nanoseconds(),
```

Two separate `time.Now()` calls mean the timestamp and elapsed time are computed at slightly different instants (microseconds apart under load). More importantly, `Timestamp` reflects wall clock at log-creation time, not the actual packet time.

**Fix:** Capture `now` once and reuse:
```go
now := time.Now().UTC()
// ...
Timestamp: now.String(),
Elapsed:   now.Sub(inserted).Nanoseconds(),
```

Also consider using the packet timestamp from the capture metadata instead of wall clock for more accurate timing.

**How to test:** Compare `Timestamp` and `Elapsed` fields in output. With the current code, `Elapsed` could occasionally appear inconsistent with the timestamp. After fixing, they will always be consistent.

---

## 11. Timestamp Format Is Non-Standard

**File:** `main.go:210`
**Severity:** Low (interoperability)

```go
Timestamp: time.Now().UTC().String(),
```

`time.Time.String()` produces a Go-specific format like `"2024-01-15 10:30:00.123456789 +0000 UTC"` which is hard to parse in downstream systems (Elasticsearch, Splunk, etc.). There's even a commented-out RFC3339 line at 209:

```go
//Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
```

**Fix:** Uncomment/use RFC3339Nano:
```go
Timestamp: now.Format(time.RFC3339Nano),
```

**How to test:** Feed output to a JSON parser and verify the `tstamp` field parses as a standard ISO 8601 datetime. Current format requires custom parsing.

---

## 12. Connection Table Unbounded Growth Under Query Floods

**File:** `main.go:326-334`
**Severity:** Medium (resource exhaustion)

If the system sees many queries without matching responses (e.g., a DNS amplification attack, or one-way traffic from a TAP), the connection table grows without bound until GC runs. With default GC interval of 3 minutes, a 100k qps flood would accumulate ~18M entries.

**Fix:** Add a maximum size check on insertion:
```go
if len(conntable.connections) > maxConnTableSize {
    stats.Incr("conntable_overflow", 1)
    return // drop the query
}
```

Make `maxConnTableSize` configurable (e.g., default 1M entries).

**How to test:** Replay a one-directional PCAP (queries only) and monitor memory usage. Without the fix, memory grows linearly with packets. With the fix, it plateaus at the configured limit.

---

## 13. `UnmarshalMsgpack` Is a No-Op

**File:** `messagepack.go:56-63`
**Severity:** Low (dead code)

```go
func (dle *dnsLogEntry) UnmarshalMsgpack(data []byte) error {
    tmp := &dnsLogEntry{}
    if err := msgpack.Unmarshal(data, &tmp); err != nil {
        return err
    }
    return nil  // unmarshaled data thrown away
}
```

This function decodes into a throwaway `tmp` and never copies the result to `dle`. It will also cause infinite recursion since `msgpack.Unmarshal` calls `UnmarshalMsgpack` on the target type.

**Fix:** Either implement it correctly or remove it. Since it's not called in production code, removing it is safer.

**How to test:** Write a round-trip test: marshal a `dnsLogEntry`, unmarshal it, and compare fields. This will currently either panic (stack overflow) or return an empty struct.

---

## 14. Config File Support Is Stubbed Out

**File:** `config.go:86-87`
**Severity:** Low (incomplete feature)

```go
if *configFile != "" {
    //load file
}
```

The `-config` flag is accepted but does nothing. Users who specify a config file get a silently empty configuration.

**Fix:** Either implement YAML/TOML config file loading or remove the flag entirely to avoid confusion.

**How to test:** Run with `-config /some/file.yaml` and verify it either works or prints a clear "not implemented" error, rather than silently starting with defaults.

---

## 15. `cleanDnsCache` Goroutine Leaks on Shutdown

**File:** `main.go:235-263`
**Severity:** Low (resource leak)

`cleanDnsCache` runs an infinite `for` loop with `time.Sleep`. There is no shutdown mechanism — it runs until the process exits. While not harmful in practice (the OS reclaims everything), it prevents clean unit testing and violates Go best practices around goroutine lifecycle.

**Fix:** Accept a `context.Context` or a `done` channel:
```go
func cleanDnsCache(ctx context.Context, ...) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            // GC logic
        case <-ctx.Done():
            return
        }
    }
}
```

**How to test:** In tests, create a context, cancel it, and verify the goroutine exits (use `runtime.NumGoroutine()` before/after).

---

## 16. `time.Tick` Leaks in `handlePacket`

**File:** `main.go:356`
**Severity:** Low (resource leak)

```go
ticker := time.Tick(time.Minute)
```

`time.Tick` creates a ticker that can never be garbage collected. The function documentation itself says "the underlying Ticker cannot be recovered by the garbage collector; it leaks." Use `time.NewTicker` and defer `Stop()`:

```go
ticker := time.NewTicker(time.Minute)
defer ticker.Stop()
// ... use ticker.C in select
```

**How to test:** Run `go vet` with the `lostcancel` checker or use `staticcheck` which flags `time.Tick` usage.

---

## 17. `LogToKafka()` Logic Is Incorrect

**File:** `log.go:73-75`
**Severity:** Low (correctness)

```go
func (lo *logOptions) LogToKafka() bool {
    return !(lo.KafkaBrokers == "" && lo.KafkaTopic == "")
}
```

This returns `true` if *either* brokers or topic is set, but both are required for a working Kafka connection. Setting only `-kafka_topic` without `-kafka_brokers` will cause a crash in `newKafkaProducer`.

**Fix:**
```go
func (lo *logOptions) LogToKafka() bool {
    return lo.KafkaBrokers != "" && lo.KafkaTopic != ""
}
```

**How to test:** Run with `-kafka_topic test` but no `-kafka_brokers`. Current behavior: crash. Expected: Kafka logging disabled with a warning.

---

## 18. Non-Query DNS Packets Are Not Filtered

**File:** `main.go:280-282`
**Severity:** Low

```go
if dns.OpCode != layers.DNSOpCodeQuery {
    log.Debug("Saw non-query DNS packet")
}
```

This logs a debug message but does not `return`. Non-query packets (zone transfers, dynamic updates) continue through the matching logic, potentially creating garbage entries in the connection table.

**Fix:** Add a `return` after the debug log.

**How to test:** Send an AXFR or dynamic update through the capture and verify it doesn't create spurious log entries.

---

## Priority Summary

| # | Issue | Severity | Effort |
|---|-------|----------|--------|
| 1 | TCP buffer overread | High | Trivial |
| 2 | No IPv6 support | High | Medium |
| 3 | Unbuffered sink channels | High | Low |
| 4 | RLock-to-Lock race | Medium | Low |
| 5 | numprocs power-of-two | Medium | Trivial |
| 6 | Stale CI | Medium | Low |
| 7 | Fragile Kafka client | Medium | High |
| 8 | Fluentd no reconnect | Medium | Low |
| 12 | Conntable unbounded growth | Medium | Low |
| 17 | LogToKafka() logic | Low | Trivial |
| 18 | Non-query not filtered | Low | Trivial |
| 9 | Encoding errors ignored | Low-Med | Trivial |
| 10 | time.Now() called twice | Low | Trivial |
| 11 | Non-standard timestamp | Low | Trivial |
| 13 | Broken UnmarshalMsgpack | Low | Trivial |
| 14 | Config file stub | Low | Low |
| 15 | GC goroutine leak | Low | Low |
| 16 | time.Tick leak | Low | Trivial |
