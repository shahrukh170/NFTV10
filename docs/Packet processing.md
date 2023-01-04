#### Metering.

This the first time a packet makes contact with the filter. This comprises of an observation point (a bridge) at which packets can be captured. Once a packet is captured, the following steps are followed:
* It's timestamped.
* A flow ID is calculated and assigned to the packet.
* Relevant fields are extracted.
* Header and payload lengths are calculated.
* If the packet has a transport layer (UDP or TCP), `sport` and `dport` fields are extracted, else, `sport` and `dport` fields are set to `0`.
* If the packet has a TCP layer, TCP flags are extracted.
* This basic packet data is then send over to the flow exporter.

#### Exporting.

This is where a flow is built, using the basic packet data received from the Metering process. Whenever a new packet is received, and a flow with an ID similar to the packet's ID isn't found, a new flow is created, else, the new packet's data is compined with the existing flow data.

After a predefined timeout, all flows older than the timeout are send over to the collecting process and removed from the exporting process flow cache.

#### Collecting.

This is the last phase in a flow-based filter packet processing workflow. The data received here is entirely flow metadata but not packet-specific data. In the exporting process, before a flow is exported to the collecting process:
* flow metatdata is built by aggregating all packet attributes.
* these metadata focuses on describing a flow by using its:
  * volume in bytes.
  * volume in number of packets.
  * volume in number packets with certain characteristics e.g number of packets with MF flag set.
  
*NB: Flow collecting is a work in progress.
