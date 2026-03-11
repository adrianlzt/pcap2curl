# pcap2curl

Read a packet capture, extract HTTP requests and turn them into cURL commands for replay.

See https://isc.sans.edu/diary.html?storyid=22900

## Installation & Usage

Run directly with uvx (no installation needed):

```
uvx --from git+https://github.com/adrianlzt/pcap2curl pcap2curl <pcap_file>
```

## Features

- TCP stream reassembly - handles HTTP requests spanning multiple packets
- Auto-detects HTTP traffic on any port
- Interactive connection selection menu
- Extracts request bodies (uses Content-Length header)
- Detects TLS/encrypted traffic (marked as non-selectable)
- Supports multiple requests per TCP connection (keep-alive/pipelining)

## Example

```
❯ uvx --from git+https://github.com/adrianlzt/pcap2curl pcap2curl capture.pcap
Found 6 HTTP connection(s):

[1] 127.0.0.1:58524 → 127.0.0.1:8000 (2 request(s))
    POST /api/v1/auth/refresh
    GET /api/v1/db-changes/stream

[2] 127.0.0.1:58530 → 127.0.0.1:8000 (2 request(s))
    POST /api/v1/cases
    GET /api/v1/cases/6/comments

[3] 127.0.0.1:58546 → 127.0.0.1:8000 (1 request(s))
    POST /api/v1/cases/

[4] 127.0.0.1:45692 → 127.0.0.1:2024 (1 request(s))
    POST /threads

[5] 127.0.0.1:45706 → 127.0.0.1:2024 (1 request(s))
    POST /threads/e08905cd-2b80-4e62-98fe-4d315aa3d318/runs/stream

[6] 127.0.0.1:56148 → 127.0.0.1:8000 (1 request(s))
    GET /api/v1/db-changes/stream

Select connections (comma-separated, e.g., 1,3): 4,5

# Connection 4: 127.0.0.1:45692 → 127.0.0.1:2024

curl 'http://localhost:2024/threads' \
 -X POST \
 -H 'Accept: */*' \
 -H 'Accept-Encoding: gzip, deflate' \
 -H 'Connection: keep-alive' \
 -H 'User-Agent: python-httpx/0.28.1' \
 -H 'baggage: user.id=1' \
 -H 'Content-Length: 138' \
 -H 'Content-Type: application/json' \
 -d '{"metadata":{"user_id":"1","environment":"production"}}'
```

## Disclaimer

Little effort is made to verify that the requests are valid. This is intended to extract well formed requests that were created by your browser. Not necessarily intended for malicious requests.

CREDIT: Stackoverflow
