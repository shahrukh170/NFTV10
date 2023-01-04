## Flow-Based Filter: Functional Requirement Specification Document

### Table of Contents

* [Overview](#overview)
* [GENERAL](#1-general)
  * [Project Description](#11-project-description)
    * [Background](#111-background)
    * [Purpose](#112-purpose)
    * [Assumptions and Constraints](#113-assumptions-and-constraints)
    * [Interfaces to External Systems](#114-interfaces-to-external-systems)
  * [Points of Contact](#12-points-of-contact)
  * [Document References](#13-document-references)
  * [Timeline](#14-timeline)
* [FUNCTIONAL REQUIREMENTS](#2-functional-requirements)
  * [Data Requirements](#21-data-requirements)
    * [NetFlow](#211-netflow)
    * [Rule](#212-rule)
  * [Functional Process Requirements](#22-functional-process-requirements)
* [OPERATIONAL REQUIREMENTS](#3-operational-requirements)
  * [Security](#31-security)
  * [Activity Logs](#32-activity-logs)
  * [Reliability](#34-reliability)
  * [Performance](#35-performance)
* [REQUIREMENTS TRACEABILITY MATRIX](#4-requirements-traceability-matrix)
* [GLOSSARY](#5-glossary)

### Overview
This functional requirements document (FRD) is a formal statement of an application’s (Flow-based Filter) functional requirements. 

### 1. GENERAL
#### 1.1 Project Description
A flow-based filter is a piece of software that is used to identify network covert channel network traffic flows in high-speed networks. In computing, a NetFlow is a feature that was introduced on network routers by Cisco ease the collection of IP network traffic as it enters and exits network interfaces. This project (Flow-Based Filter) is a work in progress, aimed at producing a rule-based flow-based network traffic analyzer that can accurately detect and eliminate network covert channels.

##### 1.1.1 Background
The Flow-Based filter project is an advancement of a previous project, a rule-based packet-based filter. The proposed Flow-Based filter is expected to achieve the following goals: provide better performance in terms of:
* To detect network covert channels in high speed networks.
* The filter method should include both methods: knowledge and behviour detections.
* The detection should include both layers header and payload.
* The filter analytics should inlude the count of used rules was used after a certain filtering process.

##### 1.1.2 Purpose
The purpose of making updates to any application is to provide improvements to existing features or add new features. The Flow-Based filter was proposed in order to address some shortcomings found in the previous packet-based filter. The Flow-Based filter is expected to:
* Ultimately, increase the NEL and beat the one (NEL time) we have with the dynamic/adaptive filter.
* Ultimately, increase packets exchanged between sender and receiver (all packets).
* Optionally, decrease CPU/RAM consumptions.

##### 1.1.3 Assumptions and Constraints
The proposed Flow-Based filter will be developed to primarily detect the existence of covert channels in networks. Network covert channels evolve everyday and new covert techniques are developed everyday too. Filter rules will be created based on statistical data obtained from known covert techniques. Any future developments in covert techniques will call for the development of a new release of the Flow-Based filter.

##### 1.1.4 Interfaces to External Systems
The proposed Flow-Based filter will be a stand-alone Python application and will not communicate with any other external system or software.


#### 1.2 Document References
* Golling, Mario, Rick Hofstede, and Robert Koch. "Towards multi-layered intrusion detection in high-speed networks." 2014 6th International Conference on Cyber Conflict (CyCon 2014). IEEE, 2014.
* Aleksandra Mileva, Boris Panajotov:Covert channels in TCP/IP protocol stack - extended version-. Central Europ. J. Computer Science 4(2): 45-66 (2014)
* [NetFlow Definition](https://github.com/Aaliif/Flow-Filter/blob/master/docs/NetFlow_Definition.md)

#### 1.3 Timeline

| Task                             | Description       | Start date         | Due date                               |
|:---------------------------------|:------------------|:-------------------|:---------------------------------------|
| Research / Information gathering | Collect and document references to any technical material used during design/implementation of the flow based filter | 15/08/2019 | Throughout the project timeline |
| Rules definition language        | Design a simple language for creating rules    | 17/08/2019 | 19/08/2019        |
| PoC & 5 icmp rules               | Implement a proof of concept flow-based filter | 19/08/2019 | 21/08/2019        |
| Create 60 rules                  | Create the first 60 rules                      | 21/08/2019 | 28/08/2019        |
| Gateway Mode                     | Implement Mode 0                               | 29/08/2019 | 05/09/2019        |
| Static Mode                      | Implement Mode 1                               | 06/09/2019 | 13/09/2019        |
| Random Mode                      | Implement Mode 2                               | 14/09/2019 | 21/09/2019        |
| Dynamic Mode                     | Implement Mode 3                               | 22/09/2019 | 29/09/2019        |
| Random Dynamic Mode              | Implement Mode 4                               | 30/09/2019 | 07/10/2019        |
| Adaptive Mode                    | Implement Mode 5                               | 08/10/2019 | 15/10/2019        |

### 2. FUNCTIONAL REQUIREMENTS
#### 2.1 Data Requirements
At the moment, there are no plans to persist any data related to the Flow-Based filter to a database. However, each NetFlow or rule has attributes that can be used describe it. 

##### 2.1.1 NetFlow definition
In literature, several definitions of an IP fow can be found. Here we follow the definition of Netflow as it was described by the IPFIX (IP Flow Information Export) working group within IETF : “A flow is defined as a set of IP packets passing an observation point in the network during a certain time interval. All packets belonging to a particular fow have a set of common properties.” In the IPFIX terminology, the common properties are called flow keys: they are, for example, source and destination addresses, source and destination port numbers and IP protocol: (ip src, ip dst, port src, port dst, proto).

This section defines the attributes used to define network traffic that belongs to the same NetFlow.

| Attr                            | Type                        | Description                                      |
|:--------------------------------|:----------------------------|:-------------------------------------------------|
| `ID`                            | *String*                    | A unique identifier assigned to each NetFlow     |
| `src`                           | *String*                    | Source IP Address                                |
| `dst`                           | *String*                    | Destination IP Address                           |
| `sport`                         | *16-bit Unsigned Integer*   | Source Port (UDP/TCP)                            |
| `dport`                         | *16-bit Unsigned Integer*   | Destination Port (UDP/TCP)                       |
| `proto`                         | *Enumeration*               | Protocol. IP, TCP, HTTP, ARP, ...                |
| `start_datetime`                | *Timestamp*                 | Time at which data exchange was initiated        |
| `end_datetime`                  | *Timestamp*                 | Time at which data echange ended                 |
| `ip_mf_flag_count`              | *64-bit Unsigned Integer*   | No. of fragmented packets                        |
| `nb_of_packets`                 | *64-bit Unsigned Integer*   | No. of packets exchanged between `src` and `dst` |
| `volume_in_bytes`               | *64-bit Unsigned Integer*   | No. of bytes exchanged between `src` and `dst`   |

**NOTE: The Definition of NetFlow attributes is subject to change**

##### 2.1.2 Rule
Each the rules will be described using the following attributes.

| Attr                              | Type                        | Description                                      |
|:----------------------------------|:----------------------------|:-------------------------------------------------|
| `protocol`                        | *Enumeration*               | Protocol, e.g., IP, TCP, ICMP, HTTP, ARP, e.t.c  |
| `conditions`                      | *String[]*                  | A list of conditions. A condition is a a cobination of a NetFlow attribute, a comparison operator, e.g. `==`, `<`, e.t.c and a literal value e.g. `["nb_of_packets >= 10000", "volume_in_bytes >= 3000"]`. |
| `action`                          | *Enumeration*               | Action to applied for each of the packets belonging the NetFlow in question, if one or more conditions evaluate to `True` |

**NOTE: The Definition of Rule attributes is subject to change**

#### 2.2 Functional Process Requirements
The flow based filter uses IPFIX (Internet Protocol Flow Information Export) which is a flexible protocol with around 280 attributes. IPFIX allows export of flow records in a custom format defined by the export template. Unlike Netflow, IPFIX contains specific fields which can be used by vendors to store proprietary information. The IPFIX architecture is based on three processes:
* Observation points with a metering process. Observation points collect the packets passing through specific interfaces. These packets are forwarded to a metering process. The metering process timestamps the packets. These timestamped packets can be sampled or filtered because the total number of packets can be very large in a high speed network. These packets are cached for specific intervals such that all packets required for a specific flow are received.
* Exporting process.The rules for generating IPFIX flow records are defined in an exporting process. The process generates the IPFIX records in the format defined by an IPFIX template and forwards them to the collecting process using the underlying transport protocol.
* Collecting process. The collecting process collects IPFIX records from exporting process and stores them in a flow database. The database is accessible to the flow-analysis applications for required purpose.

The flow-based covert channel filter takes IPFIX/Netflow records as input. The flows records can have many attributes. However, not all of these attributes will be required in the attack detection. decision. The feature selection phase only selects relevant attributes required for decision making. A pre-processing phase converts the flow records in a specific format which is acceptable to the detection algorithm. In the detection phase, the algorithm marks the flow records as covert or normal. If the flow is normal, it is considered safe and dropped with no subsequent action while covert flow can raise an alert and become the subject of further inspection.

### 3. OPERATIONAL REQUIREMENTS
#### 3.1 Security
#### 3.2 Activity Logs
#### 3.4 Reliability
#### 3.5 Performance
### 4. REQUIREMENTS TRACEABILITY MATRIX
### 5. GLOSSARY
