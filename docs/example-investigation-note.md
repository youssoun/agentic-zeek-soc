# DNS beaconing 10.0.0.5

## Lead
10.0.0.5 → cdn-update.example.com

## Evidence (wire)
- DNS queries to `cdn-update.example.com`: **6**
- sample names: ['cdn-update.example.com', 'cdn-update.example.com', 'cdn-update.example.com', 'cdn-update.example.com', 'cdn-update.example.com']
- protocols seen: ['tcp']
- top peers: ['10.0.0.20', '192.0.2.44']

## Verdict
suspicious (confidence: medium)

## Next checks
- interval regularity across `conn` sessions
- response size pattern (tunneling check)
- TLS SNI match on the same host pair

