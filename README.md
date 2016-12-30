# packetDecoder
Decrypts raw pcap files.

Usage:
---
1. Place ropcap.py into root of OpenKore folder.
2. Run python ropcap.py <original.pcap> <output.pcap>. The output.pcap will be the decrypted traffic.

Issue:
---
This script is not practical because it cannot determine whether a single packet contains more than one messageID (header) or not. It will decrypt packets according to the number of packets in pcap file only.
