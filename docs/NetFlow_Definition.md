## NetFlow Definition.

In literature, several definitions of an IP fow can be found. Here we follow the definition of Netflow as
it was described by the IPFIX (IP Flow Information Export) working group within IETF :
“A flow is defined as a set of IP packets passing an observation point in the network during a certain
time interval. All packets belonging to a particular fow have a set of common properties.”
In the IPFIX terminology, the common properties are called
flow keys: they are, for example, source and destination addresses, source and destination port numbers and IP protocol: (ip src, ip dst, port src, port dst, proto).

This section defines the attributes used to define network traffic that belongs to the same NetFlow.

| Attr                            | Description                                      |
|:--------------------------------|:-------------------------------------------------|
| `ID` 	                          | A unique identifier assigned to each NetFlow     |
| `src`                           | Source IP Address                                |
| `dst`                           | Destination IP Address                           |
| `sport` 	                      | Source Port (UDP/TCP)                            |
| `dport` 	                      | Destination Port (UDP/TCP)                       |
| `proto` 	                      | Protocol. IP, TCP, HTTP, ARP, ...                |
| `start_datetime`                | Time at which data exchange was initiated        |
| `end_datetime`            	    | Time at which data echange ended                 |
| `ip_mf_flag_count`              | No. of fragmented packets                        |
| `nb_of_packets`                 | No. of packets exchanged between `src` and `dst` |
| `volume_in_bytes`               | No. of bytes exchanged between `src` and `dst`   |
