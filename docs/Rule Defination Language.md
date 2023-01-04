## Rule Defination Language.

This document provides a simplified description of the language to be used to create rules for the flow-based filter. This Rule Definition Language is inspired by the expression language used by Snort 3 and the data encoding using for HTTP `application/x-www-form-urlencoded` Content-Type.

### Defination.
A rule follows a specific format:

`Action` `Protocol` `Networks` `Ports` `Direction Operator` `Networks` `Ports` `X-www-form-urlencoded NetFlow Features`

#### Action.
This parameter defines whether packets belonging to a certain NetFlow will be `drop`ped, `forward`ed
or `normalize`d. The value for action can only one of the following:
* drop
* forward
* normalize

This field is not optional.

#### Protocol.
This is the network protocol for a certain target NetFlow. This field can be set to any of the standard protocol names. The protocol names must be in lowercase. E.g.

| Protocol (Full name)                  | Rule protocol name                                        |
|:--------------------------------------|:----------------------------------------------------------|
| Transport Control Protocol            | `tcp`                                                     |
| Domain Name System                    | `dns`                                                     |

This field is optional. In case the network protocol is not of much interest, it's value should be set to `any`.

#### Networks.
This is a comma-separated list of networks or (and) IP addresses. This can either be the source network/IP address depending on the `Direction Operator`. The parameter is used twice: Before and after the `Direction Operator`. If a network is provided, a range of IP addresses is targeted by the rule. E.g. 192.168.100.1/24,10.10.23.1,72.16.63.1.

This parameter can also be defined using the following macros:
* EXTERNAL_NET
* HOME_NET

These macros are initialized during start-up. This field is optional. In case the network(s) is (are) not of much interest, it's value should be set to `any`.

#### Ports.
A comma-separated list of all ports targeted by the rule. The parameter is used twice: Before and after the `Direction Operator`. A port can not be `0` or greater than `65535`. E.g. 22,443,8080.

This field is optional. In case the port(s) is (are) not of much interest, it's value should be set to `any`. To target Non-Transport Layer traffic, set this parameter to `any`. 

#### Direction Operator.
Defines the source and destination of targeted network traffic. This parameter can either be `->` or `<-`. The arrow points to the destination of the flow. The network(s) and port(s) pointed to by the arrow is(are) the destination of the flow.

#### X-www-form-urlencoded NetFlow Features.
Calling this set of parameters `x-www-form-urlencoded` is a misnormer because keys and values are separated by either one of the comparison operators, but not the `=` symbol. According to the [Netflow Definition](https://github.com/Aaliif/Flow-Filter/blob/master/docs/NetFlow_Definition.md), a net flow has 11 characteristics. There are only 3 of them that can be used as `x-www-form-urlencoded` features. Namely:
* ip_mf_flag_count
* nb_of_packets
* volume_in_bytes

All these parameters should be set to unsigned integer values. E.g. ip_mf_flag_count==100&nb_of_packets>=9000&volume_in_bytes>80000.

This field is optional.

### Examples.

#### #1
Block ICMP netflows from 192.168.0.1 or 192.168.0.5 to 1.1.1.1 or 8.8.8.8 if the aggregated traffic volume in bytes goes beyond 8000 and the number of packets exchanged goes beyond 9000, within a specified period of time.

```
drop icmp 192.168.0.1,192.168.0.5 any -> 1.1.1.1,8.8.8.8 any nb_of_packets>9000&volume_in_bytes>80000
```

#### #2
Allow data exchange between web servers and web clients.

```
forward tcp any any -> 8080,80,443
```

#### #3
Normalize all packets flowing through the bridge for a certain IP netflow if the number of fragmented packets for that netflow exceeds 1000, within a specified period of time.
```
normalize ip any any -> any any ip_mf_flag_count>1000
```

NOTE: We haven't discussed about how normalization will occur.




