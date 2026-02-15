#!/usr/bin/env bash
#
# Creates GitHub issues for the gopassivedns architecture review findings.
# Requires: gh CLI authenticated (run `gh auth login` first)
# Usage: ./create_issues.sh
#
set -euo pipefail

REPO="Phillipmartin/gopassivedns"

create_issue() {
  local title="$1"
  local labels="$2"
  local body="$3"
  echo "Creating issue: $title"
  gh issue create --repo "$REPO" --title "$title" --label "$labels" --body "$body"
  sleep 1  # rate limit courtesy
}

# ─── Issue 1: TCP buffer overread ───
create_issue \
  "Bug: TCP reassembly appends entire buffer instead of bytes read" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `main.go:123`, `dnsStream.run()` appends the entire 4096-byte `tmp` buffer to `data` regardless of how many bytes were actually read:

```go
data = append(data, tmp...)
```

## Impact

- **Severity:** High (correctness bug)
- Uninitialized/stale buffer data gets appended for any read shorter than 4096 bytes
- Wastes memory proportional to the number of short reads
- Could cause subtle issues with multiple DNS messages on the same TCP connection

## Suggested Fix

```diff
-data = append(data, tmp...)
+data = append(data, tmp[:count]...)
```

## How to Test

Create a test PCAP with a TCP DNS response smaller than 4096 bytes. Compare the parsed DNS payload before and after the fix. The current code may produce valid results by accident (the length-prefix parsing truncates), but it wastes memory and could cause subtle issues.

## References

- File: `main.go:123`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #1
EOF
)"

# ─── Issue 2: No IPv6 support ───
create_issue \
  "No IPv6 support — all IPv6 DNS traffic silently dropped" \
  "enhancement" \
  "$(cat <<'EOF'
## Summary

The packet capture loop's load-balancing parser (`main.go:544-551`) only decodes `layers.Ethernet` and `layers.IPv4`. Any IPv6 DNS traffic is silently dropped at line 568:

```go
if foundLayerType(layers.LayerTypeIPv4, foundLayerTypes) {
```

Similarly, `packetData.ipLayer` in `packets.go:26` is hardcoded to `*layers.IPv4`.

## Impact

- **Severity:** High (feature gap)
- IPv6 DNS traffic is increasingly common and is completely invisible to this tool
- No error or warning is emitted when IPv6 packets are encountered and dropped

## Suggested Fix

1. Add `layers.IPv6` to the decoding layer parser in `main.go`
2. Add an `ip6Layer *layers.IPv6` field to `packetData` struct
3. Update `GetSrcIP`/`GetDstIP` to check for IPv6 layer
4. Update the load balancer hash to use whichever IP layer is present

## How to Test

1. Capture DNS queries to an IPv6-only resolver (e.g., `dig @2001:4860:4860::8888 example.com`)
2. Feed the PCAP to gopassivedns
3. Verify log output is produced — currently it will produce nothing

## References

- Files: `main.go:544-551,568`, `packets.go:26`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #2
EOF
)"

# ─── Issue 3: Unbuffered sink channels ───
create_issue \
  "Unbuffered log sink channels create backpressure bottleneck" \
  "bug" \
  "$(cat <<'EOF'
## Summary

All per-sink channels in `log.go:165-195` are created unbuffered:

```go
stdoutChan := make(chan dnsLogEntry)
```

The fan-out loop in `logConn()` sends to each sink sequentially:

```go
for _, logChan := range logs {
    logChan <- message
}
```

If *any* sink blocks (Kafka reconnecting, syslog slow, stdout pipe full), the entire fan-out blocks, which backs up the main `logC` channel, which backs up all packet processing workers. A single slow sink stalls the entire capture pipeline.

## Impact

- **Severity:** High (performance bottleneck)
- A single slow or failing sink stalls all other sinks and packet capture
- Under high traffic, this can cause kernel-level packet drops at the capture interface

## Suggested Fix

Buffer each sink channel (e.g., 1000 entries) and add a non-blocking send with a drop counter:

```go
select {
case logChan <- message:
default:
    stats.Incr("log_dropped", 1)
    log.Debug("Dropping log entry due to slow sink")
}
```

## How to Test

1. Set up a Kafka sink pointed at an unreachable broker
2. Send DNS traffic through the capture
3. Measure whether stdout logging continues or freezes
4. With the fix, stdout should remain responsive even with Kafka down

## References

- File: `log.go:158-215`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #3
EOF
)"

# ─── Issue 4: RLock-to-Lock race ───
create_issue \
  "Race condition: RLock-to-Lock upgrade in handleDns allows duplicate log entries" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `main.go:296-334`, `handleDns` reads the connection table under `RLock`, releases it, then acquires a write `Lock`:

```go
conntable.RLock()
item, foundItem := conntable.connections[uid]
if foundItem {
    conntable.RUnlock()
    conntable.Lock()
    delete(conntable.connections, uid)
    conntable.Unlock()
```

Between `RUnlock()` and `Lock()`, another goroutine can modify the map, creating a TOCTOU (time-of-check-time-of-use) race condition.

## Impact

- **Severity:** Medium
- Two goroutines could both find the same entry, both try to delete it, and both produce duplicate log entries
- Two goroutines could both miss an entry, both try to insert, and one overwrites the other

## Suggested Fix

Use a single `Lock()` for the entire check-and-modify operation:

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

## How to Test

Write a concurrent test that sends the same DNS query ID from multiple goroutines simultaneously. Check that exactly one log entry is produced per matched query-response pair.

## References

- File: `main.go:296-334`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #4
EOF
)"

# ─── Issue 5: numprocs power of two ───
create_issue \
  "Worker channel distribution broken for non-power-of-two numprocs values" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `main.go:561,570`, packet distribution to worker channels uses bitwise AND:

```go
channels[int(ipLayer.NetworkFlow().FastHash())&(config.numprocs-1)] <- pd
```

This only correctly distributes across all channels when `numprocs` is a power of two. If a user passes `-numprocs 12`, channels 8-11 will never receive packets.

## Impact

- **Severity:** Medium (silent misconfiguration)
- Non-power-of-two values cause some worker goroutines to sit idle
- No warning or error is emitted

## Suggested Fix

Either enforce power-of-two at startup or use modulo:

```go
channels[int(ipLayer.NetworkFlow().FastHash()) % config.numprocs] <- pd
```

## How to Test

Run with `-numprocs 3` and a large PCAP. Check StatsD per-thread counters — with the current code, some channels will receive zero packets. After the fix, all three should receive traffic.

## References

- Files: `main.go:561,570`, also in `gracefulShutdown` at line 626
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #5
EOF
)"

# ─── Issue 6: Stale CI ───
create_issue \
  "CI configuration is stale — tests Go 1.5-1.7 but codebase requires 1.24+" \
  "enhancement" \
  "$(cat <<'EOF'
## Summary

`.travis.yml` tests against Go 1.5, 1.6, and 1.7, but `go.mod` declares `go 1.24.7`. These old Go versions cannot compile the codebase. Travis CI is also largely deprecated.

## Impact

- **Severity:** Medium (operational)
- CI is effectively non-functional
- No automated testing on pull requests

## Suggested Fix

Migrate to GitHub Actions. Test against Go 1.23 and 1.24:

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

## How to Test

Push to a branch and verify CI passes on both Go versions. Confirm the old Travis config can be removed.

## References

- File: `.travis.yml`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #6
EOF
)"

# ─── Issue 7: Fragile Kafka client ───
create_issue \
  "Custom Kafka client is fragile — no batching, no failover, deprecated API version" \
  "enhancement" \
  "$(cat <<'EOF'
## Summary

The custom Kafka producer (`kafka.go`) has several limitations:
- Only connects to one broker (no failover if that broker goes down)
- Always writes to partition 0 — no partitioning strategy
- Sends one message per TCP write (no batching) — extremely inefficient at scale
- Uses Kafka API v0, which is deprecated in modern Kafka clusters
- Doesn't parse produce response error codes (line 112: "a successful read is good enough")
- CRC32 comment contradicts itself (says "Castagnoli" but implements IEEE)

## Impact

- **Severity:** Medium (reliability)
- Kafka output is slow without batching
- No resilience to broker failures
- Silent data loss if produce response contains errors

## Suggested Fix

Consider replacing with `segmentio/kafka-go` (lighter than Sarama but production-grade). If keeping the custom client:
- Implement message batching (collect N messages or flush every M ms)
- Parse the produce response to detect actual errors
- Support broker failover (round-robin on send failure)
- Add partition selection (hash on question domain)

## How to Test

- Benchmark current vs. batched throughput with a Kafka broker
- Test broker failover by killing one broker in a multi-broker setup
- Verify error responses (produce to a non-existent topic) are logged

## References

- File: `kafka.go`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #7
EOF
)"

# ─── Issue 8: Fluentd no reconnect ───
create_issue \
  "Fluentd socket write failure kills the entire process instead of reconnecting" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `log.go:318-344`, if the fluentd Unix socket connection drops after initial connect, the next `conn.Write()` fails and the program calls `log.Fatalf(...)`, terminating the entire process:

```go
if err != nil {
    log.Fatalf("Unable to write to UNIX Socket %+v with err %+v\n", opts.FluentdSocket, err)
}
```

## Impact

- **Severity:** Medium (reliability)
- A fluentd restart causes gopassivedns to crash
- Particularly problematic in containerized environments where fluentd may restart independently

## Suggested Fix

Wrap the write in a reconnect loop:

```go
if _, err = conn.Write(encoded); err != nil {
    log.Errorf("Fluentd write failed: %s, reconnecting...", err)
    conn.Close()
    conn = fluentdSocket(opts.FluentdSocket)
    // retry write once
}
```

## How to Test

Start gopassivedns with fluentd output, restart the fluentd process, and verify gopassivedns reconnects rather than crashing.

## References

- File: `log.go:318-344`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #8
EOF
)"

# ─── Issue 9: Encoding errors ignored ───
create_issue \
  "Syslog and stdout sinks silently discard JSON encoding errors" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `log.go:220` and `log.go:312`, the JSON encoding error is silently discarded:

```go
encoded, _ := message.Encode()  // error discarded
```

If JSON encoding fails (e.g., due to an unusual IP representation), garbled or empty data gets written.

## Impact

- **Severity:** Low-Medium
- Silent data corruption in output

## Suggested Fix

```go
encoded, err := message.Encode()
if err != nil {
    log.Errorf("Failed to encode log entry: %s", err)
    continue
}
```

## How to Test

Create a `dnsLogEntry` with a nil `Server` IP field and confirm the error is logged rather than producing `"dst":null` or panicking.

## References

- Files: `log.go:220`, `log.go:312`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #9
EOF
)"

# ─── Issue 10: time.Now() called twice ───
create_issue \
  "time.Now() called twice per log entry causes inconsistent timestamps" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `main.go:186-188` and `main.go:210-211`:

```go
Timestamp: time.Now().UTC().String(),
Elapsed:   time.Now().Sub(inserted).Nanoseconds(),
```

Two separate `time.Now()` calls mean the timestamp and elapsed time are computed at slightly different instants.

## Impact

- **Severity:** Low (inaccuracy)
- Timestamp and elapsed time are inconsistent with each other

## Suggested Fix

```go
now := time.Now().UTC()
Timestamp: now.String(),
Elapsed:   now.Sub(inserted).Nanoseconds(),
```

## References

- File: `main.go:186-188,210-211`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #10
EOF
)"

# ─── Issue 11: Non-standard timestamp format ───
create_issue \
  "Timestamp uses Go-specific format instead of RFC3339" \
  "enhancement" \
  "$(cat <<'EOF'
## Summary

`main.go:210` uses `time.Time.String()` which produces a Go-specific format like `"2024-01-15 10:30:00.123456789 +0000 UTC"`. This is hard to parse in downstream systems. There is even a commented-out RFC3339 alternative at line 209:

```go
//Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
```

## Impact

- **Severity:** Low (interoperability)
- Downstream systems (Elasticsearch, Splunk, etc.) require custom parsing

## Suggested Fix

Use RFC3339Nano format:

```go
Timestamp: now.Format(time.RFC3339Nano),
```

**Note:** This is a breaking change for any consumers parsing the current format.

## References

- File: `main.go:209-210`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #11
EOF
)"

# ─── Issue 12: Connection table unbounded growth ───
create_issue \
  "Connection table grows without bound under query floods" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `main.go:326-334`, if the system sees many queries without matching responses (e.g., a DNS amplification attack, or one-way traffic from a TAP), the connection table grows without bound until GC runs. With default GC interval of 3 minutes, a 100k qps flood would accumulate ~18M entries.

## Impact

- **Severity:** Medium (resource exhaustion)
- Memory exhaustion under adversarial or one-directional traffic
- OOM kill in production

## Suggested Fix

Add a maximum size check on insertion:

```go
if len(conntable.connections) > maxConnTableSize {
    stats.Incr("conntable_overflow", 1)
    return
}
```

Make `maxConnTableSize` configurable (e.g., default 1M entries).

## How to Test

Replay a one-directional PCAP (queries only) and monitor memory usage. Without the fix, memory grows linearly. With the fix, it plateaus at the configured limit.

## References

- File: `main.go:326-334`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #12
EOF
)"

# ─── Issue 13: UnmarshalMsgpack is broken ───
create_issue \
  "UnmarshalMsgpack is a no-op and causes infinite recursion" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `messagepack.go:56-63`:

```go
func (dle *dnsLogEntry) UnmarshalMsgpack(data []byte) error {
    tmp := &dnsLogEntry{}
    if err := msgpack.Unmarshal(data, &tmp); err != nil {
        return err
    }
    return nil  // unmarshaled data thrown away
}
```

This function:
1. Decodes into a throwaway `tmp` and never copies the result to `dle`
2. Causes infinite recursion since `msgpack.Unmarshal` calls `UnmarshalMsgpack` on the target type

## Impact

- **Severity:** Low (dead code / crash if called)
- Not called in production, but dangerous if anyone tries to use it

## Suggested Fix

Remove the function entirely since it's unused, or implement correctly.

## How to Test

Write a round-trip test: marshal a `dnsLogEntry`, unmarshal it, and compare fields. Currently this will panic with stack overflow.

## References

- File: `messagepack.go:56-63`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #13
EOF
)"

# ─── Issue 14: Config file stub ───
create_issue \
  "Config file flag (-config) is accepted but does nothing" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `config.go:86-87`, the `-config` flag is accepted but the implementation is a stub:

```go
if *configFile != "" {
    //load file
}
```

Users who specify a config file silently get an empty configuration.

## Impact

- **Severity:** Low (incomplete feature)
- Silent misconfiguration

## Suggested Fix

Either implement config file loading (YAML/TOML) or remove the flag and print a clear error.

## References

- File: `config.go:86-87`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #14
EOF
)"

# ─── Issue 15: GC goroutine never exits ───
create_issue \
  "cleanDnsCache goroutine has no shutdown mechanism" \
  "enhancement" \
  "$(cat <<'EOF'
## Summary

`cleanDnsCache` in `main.go:235-263` runs an infinite `for` loop with `time.Sleep`. There is no mechanism to stop it — it runs until the process exits.

## Impact

- **Severity:** Low (resource leak)
- Prevents clean unit testing and violates Go best practices for goroutine lifecycle

## Suggested Fix

Accept a `context.Context` or `done` channel:

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

## How to Test

In tests, create a context, cancel it, and verify the goroutine exits (use `runtime.NumGoroutine()` before/after).

## References

- File: `main.go:235-263`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #15
EOF
)"

# ─── Issue 16: time.Tick leak ───
create_issue \
  "time.Tick in handlePacket leaks ticker resources" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `main.go:356`:

```go
ticker := time.Tick(time.Minute)
```

`time.Tick` creates a ticker that can never be garbage collected. The Go documentation says: "the underlying Ticker cannot be recovered by the garbage collector; it leaks."

## Impact

- **Severity:** Low (resource leak)
- One leaked ticker per worker goroutine

## Suggested Fix

```go
ticker := time.NewTicker(time.Minute)
defer ticker.Stop()
// use ticker.C in select
```

## References

- File: `main.go:356`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #16
EOF
)"

# ─── Issue 17: LogToKafka logic incorrect ───
create_issue \
  "LogToKafka() returns true when only one of brokers/topic is set, causing crash" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `log.go:73-75`:

```go
func (lo *logOptions) LogToKafka() bool {
    return !(lo.KafkaBrokers == "" && lo.KafkaTopic == "")
}
```

This returns `true` if *either* brokers or topic is set, but both are required. Setting only `-kafka_topic` without `-kafka_brokers` will crash in `newKafkaProducer`.

## Impact

- **Severity:** Low (crash on misconfiguration)
- Should fail gracefully with a warning

## Suggested Fix

```go
func (lo *logOptions) LogToKafka() bool {
    return lo.KafkaBrokers != "" && lo.KafkaTopic != ""
}
```

## How to Test

Run with `-kafka_topic test` but no `-kafka_brokers`. Current behavior: crash. Expected: Kafka logging disabled with a warning.

## References

- File: `log.go:73-75`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #17
EOF
)"

# ─── Issue 18: Non-query DNS not filtered ───
create_issue \
  "Non-query DNS packets (AXFR, updates) are not filtered, pollute connection table" \
  "bug" \
  "$(cat <<'EOF'
## Summary

In `main.go:280-282`:

```go
if dns.OpCode != layers.DNSOpCodeQuery {
    log.Debug("Saw non-query DNS packet")
}
```

This logs a debug message but does **not** `return`. Non-query packets (zone transfers, dynamic updates) continue through the matching logic, potentially creating garbage entries in the connection table.

## Impact

- **Severity:** Low
- Spurious entries in connection table and log output

## Suggested Fix

```go
if dns.OpCode != layers.DNSOpCodeQuery {
    log.Debug("Saw non-query DNS packet")
    return
}
```

## How to Test

Send an AXFR or dynamic update through the capture and verify it doesn't create spurious log entries.

## References

- File: `main.go:280-282`
- Architecture review: `ARCHITECTURE_REVIEW.md` finding #18
EOF
)"

echo ""
echo "All 18 issues created successfully!"
