## IPFIX Reference Doc.

IPFIX (Internet Protocol Flow Information Export) is:
* An [IETF](https://en.wikipedia.org/wiki/IETF) protocol.
* Created because of the common need for a standard way of exporting IP flow data from network devices.

**NB:** [`NetFlow`](https://en.wikipedia.org/wiki/NetFlow) is a Cisco Systems' proprietary technology.

#### Architecture.

* Data packets are collected at one/more `Observation Points` by a pool of `metering processes`.
* An `Exporter` then gathers each of the `Observation Points` together into an `Observation Domain`.
* The `Exporter` sends this information via the IPFIX protocol to a `Collector`.

> Exporters and Collectors are in a many-to-many relationship: One Exporter can send data to many Collectors and one Collector can receive data from many Exporters.

#### Protocol.

Just like NetFlow, IPFIX considers a flow to be a collection of packets that share a certian set of features. These packets are observed within a specified period of time. IPFIX is a `push protocol` i.e. senders send IPFIX messages to receivers periodically, without any interactive involvement on the part of the receivers.

#### Message.

An IPFIX message consists of:
* Header.
* One/more `Set`s

##### Message Header format.

Following are the message header field descriptions:

| Field              | Description                                                                                       |
|:-------------------|:--------------------------------------------------------------------------------------------------|
| Version            | Version of Flow Record format that is exported in this message. The value of this field is 0x000a for the current version, incrementing by one the version that is used in the NetFlow services export version 9.                  |
| Length             | Total length of the IPFIX Message, which is measured in octets, including Message Header and Sets.|
| Time of export     | Time (in secs) since Epoch                                                                        |
| Sequence Number    | Incremental sequence counter-modulo 2^32 of all IPFIX Data Records sent on this PR-SCTP stream from the current Observation Domain by the Exporting Process. This value must be used by the Collecting Process to identify whether any IPFIX Data Records are missed.                                                                                           |
| Observation Domain ID | A 32-bit identifier of the Observation Domain that is locally unique to the Exporting Process. |

##### Message Set format.

A `Set` is a term that refers to a collection of records that have the same structure. There are three different types of sets:
* Data Set
* Template Set
* Options Template Set

Every Set contains a common header. Following are the message header field descriptions:

| Header        | Description                                                                    |
|:--------------|:-------------------------------------------------------------------------------|
| Set ID        | Set ID value identifies the Set. A value of 2 is reserved for the Template Set. A value of 3 is reserved for the Option Template Set. All other values 4-255 are reserved for future use. Values more than 255 are used for Data Sets. The Set ID values of 0 and 1 are not used for historical reasons.                                        |
| Length        | Total length of the Set, in octets, including the Set Header, all records, and the optional padding. Because an individual Set MAY contain multiple records, the Length value must be used to determine the position of the next Set. |

#### References.

* [https://en.wikipedia.org/wiki/IP_Flow_Information_Export](https://en.wikipedia.org/wiki/IP_Flow_Information_Export)
* [https://www.ibm.com/support/knowledgecenter/en/SSCVHB_1.2.1/collector/cnpi_ipfix_message_format.html](https://www.ibm.com/support/knowledgecenter/en/SSCVHB_1.2.1/collector/cnpi_ipfix_message_format.htmlhttps://www.ibm.com/support/knowledgecenter/en/SSCVHB_1.2.1/collector/cnpi_ipfix_message_format.html)
* http://www.hjp.at/doc/rfc/rfc3917.html




