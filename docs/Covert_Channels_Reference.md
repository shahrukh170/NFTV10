# TCP/IP Covert Channel Techniques.

## IP layer.

### IP header.

Have redundancy and normally during transmission, they aren't used.
Easy elimination by traffic normalizers.

* Identification - ID - 16-bit - ASCII character
* Flags
* Fragment offset
* Options

#### Fragmentaion.
Unfragmented datagram: MF =0 , DF = 0, Fragment Offset = 0
If communication parties know the MTU (Maximum Transmission Unit) of their network, they can use the DF bit for sending 1-bit data per packet, or combination of DF bit and Identification field for sending 17-bit data per packet, by sending packets with sizes below the MTU.

If communication parties do not know the MTU, they can send 8-bit per packet, by filling high 8 bits of the Identification field (The low 8 bits are generated randomly) with result of xoring of the first fixed 8-bits of the IP header and 8-bit data.

#### Identification and Fragment Offset.
* Provides 29-bits for any unfragmented datagram
* Works for neighboring hosts

First, they check if the receiving datagram has fragmentation (MF = 1). In the negative case, they use some of the three reserved bits in the header as an indicator whether the data carries a message or not, and then they put the data in the datagram’s Identificationand Fragment Offset fields.

#### Others.

* Dividing the original IP packet into a predefined number of fragments (for example, even number will be binary 0,and odd number will be binary 1) - 1 bit per packet is send
* Using legitimate fragment with steganogram inserted into payload -NF·FS bits per packet are send, where NF is the number of fragments for that packet and the FS is the size of the fragment. It has a big covert rate and uses legitimate fragments, so it is harder to detect.

* Using different rates for packet fragmentation (for example, one rate will be binary 1, and other will be binary 0)-log2hbits per packet are send, wherehis the number of packets generation rate.

* Inter-packet delays (IPD) for encoding data.

### Internet Control Message Protocol (ICMP).
Connectionless protocol in the Internet Protocol used to transfer error messages and other infor between nodes.
##### NB:
* There are 14 (16 deprecated) types of ICMP messages.
* Header is 8 bytes.

##### IP-over-ICMP.
*Implementation*
* A covert channel by putting arbitrary information tunnelling in the payload of ICMP Echo Request and ICMP Echo Reply packets.
* Using the 32-bit reserved field in the ICMP Router Solicitation Message 

*Examples*
* ICMP-Chat
* Skeeve
* ICMPTX

### Dynamic Host Configuration Protocol (DHCP).
Allows a server to assign a host an IP address from a defined range of IP addresses.

*Covert channels over DHCP use:*
* `32-bit XID` field, which is randomly generated by the client. This is stealthier, but with limited bandwidth.
* `SECS` field, for transmitting one bit.
* the last 10B of the `CHADDR` field, when 48-bits Ethernet MAC address is used.
* 64-byte `SNAME` and 128-byte FILE fields consist of null-terminated strings, thus hidden data might be included
after this character without negatively impacting other clients or servers.
* variable-length `Option Value` field, and by the number of options used or the way options are ordered.

### Address Resolution Protocol (ARP).
A protocol for resolution of the IP address into a physical address such as an Ethernet address.
* using the last 8 bits of the `Target protocol address` field.

## Transport layer.

`TCP` and `UDP`.

### TCP & UDP.

Connection-oriented protocol.

*Implementation*
* using 32-bit `Initial Sequence Number` (ISN).
* `Acknowledge Sequence Number` field.
* redundancy present in some combination of six flag bits (URG, ACK, PSH, RST, SYN, FIN). From 64 possible combinations, 29 are valid. If the `URG` bit is not set, one can use the TCP `Urgent Pointer` field for creating covert channel with 16 bits per packet. One can use `Reserved` field for sending 4 bits per segment.
* TCP timestamps, by the modification of their low order bit. This method slows the TCP stream so that the timestamps on segments are valid when they are sent. 1-bit-per-segment covert channel can be obtained by comparing the low order bit of every TCP timestamp with the current message bit. If they match the segment is sent immediately with generated TCP timestamp, otherwise it is delayed for one timestamp tick and TCP timestamp is incremented. 
* A timing covert channel by reordering of TCP segments and using the Sequence Number field and suitably defined mathematical model.
* By modification of the `Acknowledge Sequence Number` field.
* Embedding covert messages into pure TCP ACK packets from single or multiple TCP connections, using the combinatorial approach.
* Using all TCP retransmission mechanisms: RTO (Retransmission Timeout), FR/R (Fast Retransmit/Recovery) and SACK (Selective ACK). The main idea behind RSTEG is to not acknowledge a successfully received TCP segment in order to intentionally invoke retransmission. The retransmitted segment carries a steganogram instead of user data in the payload field.
* One covert channel in UDP can be created by presence or absence of the Checksum field in the datagram, because this field is optional in UDP.

## Application layer.

HTTP, FTP, DNS, RTP, RTCP, SIP, SDP, etc.

### HyperText Transfer Protocol (HTTP).

* Using header and/or body of the HTTP request/response. There is no limit from the protocol itself in the size of the HTTP header or the body. But the size of all HTTP headers together depends on the platform - Apache servers accept headers with size up to 8KB, IIS up to 8KB or 16KB depending on the version.
* An anonymous overlay network by exploiting the web browsing activities of regular users. The protocol uses five HTTP/HTML mechanisms: redirects, cookies, Referer headers, HTML elements and Active contents.
* Hiding data in HTTP using the fact that HTTP treats any amount of consequent linear white space characters (optional line feed [CLRF], spaces [SP] and tabs [HT]) present in the header, in the same way as a single space character.
* Headers come in no specified order, so it is possible to embed data in the ordering of the headers.
* Header names are case-insensitive, so using the different capitalisation of the header values can be used for covert channel.
* A tunnel using the HTTP Entity tags (ETag and If-ŋNone-ŋMatch headers), which allows a client to verify whether its locally cached copy is still current.
* Exploiting the weakness in the CONNECT method, an arbitrary connection can be made through a HTTP proxy server and even a VPN can be established.
* A Content-ŋ MD5 header can be used for transferring up to 128 bits of data per HTTP message.
* Modulating the least significant bits of the date-based fields such as `Date` and `Last-Modified`.
* Covert timing channel using HTTP, in which a web server sends covert data to a client by delaying a response (binary 1) or responding immediately (binary 0).
* Using cookies for creating covert channels in HTTP.
* Tunneling SSH over HTTP proxy - Corkscrew.
* Tunneling TCP or UDP over HTTP - HTTunnel.
* Infranet is a framework which uses covert channels in HTTP to circumvent censorship. Infranet’s web servers receive covert requests for censured web pages encoded as a sequence of HTTP requests to harmless web pages and return their content hidden inside harmless images using steganography.

### File Transfer Protocol (FTP).

* Encoding covert bits directly into the FTP commands, so if there are N commands, every command will represent log 2 N bits.
* Varying the number of FTP NOOP commands sent during idle periods. The number of sent NOOP commands is equal to the integer value of the covert data. Before sending a new value, an ABOR command needs to be sent. For FTP, it is normal to send NOOP or ABOR continually to prevent the control connections from entering the idle status.

### Domain Name System (DNS).

Very suitable for creating covert channels for tunnelling other protocols, for example IP, TCP or UDP over DNS. Specially interested are NS, CNAME and TXT records with length up to 255B, and experimental NULL record with length up to 65536B (300B-1200B in implementations).

#### IPv4-over-DNS

`Nameserver Transfer Protocol (NSTX)`, `DNSCat`, `OzymanDNS`, `Anonymous`, `DNS2TCP`, `TUNS`, and `Iodine`.
Splitting IP packets into several chunks, send them separately, then reassemble the IP packets at the other endpoint.

*Implementation*

* TXT records
* CNAME records
* Negative caching
* Domain Name








