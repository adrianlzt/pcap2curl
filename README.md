# pcap2curl
Read a packet capture, extract HTTP requests and turn them into cURL commands for replay.

See https://isc.sans.edu/diary.html?storyid=22900

This is a simple (too simple?) Python script that will read a pcap, find HTTP requests and turn them into cURL commands for replay.

Little effort is made to verify that the requests are valid. This is intended to extract well formed requests that were created by your browser. Not necessarily intended for malicious requests.

The tool reassembles TCP streams and can handle HTTP requests spanning multiple packets. It detects all HTTP connections in a pcap file and presents an interactive menu for selection. TLS/encrypted traffic is detected and marked as non-selectable.

DISCLAIMER: I am not a Python coder. I do not like Python. I have to use it once in a while because I love [Scapy](http://www.secdev.org/projects/scapy/).

CREDIT: Stackoverflow
