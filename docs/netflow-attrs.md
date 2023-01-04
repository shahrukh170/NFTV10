
| Attr                        | Description |
|:----------------------------|:------------|
| id                          | Net flow ID |
| src                         | Source IP Address |
| dst                         | Destination IP Address |
| sport                       | Source Port (UDP/TCP) |
| dport                       | Destination Port (UDP/TCP) |
| proto                       | Protocol |
| flow_start                  | Time at which data exchange was initiated |
| flow_end                    | Time at which data echange ended |
| label                       | Net flow type as predicted by the IDS |
| flow_Duration               | Time taken from start to end of the net flow |
| total_fwd_packets           | No. of packets send from source IP to destination IP |
| total_bwd_packets           | No. of packets send from destination IP to source IP |
| total_length_of_fwd_packets | NO. of bytes send from source IP to destination IP |
| total_length_of_bwd_packets | No. of bytes send from destination IP to source IP |
| fwd_packet_length_max       | Largest packet (bytes) send from source IP to destination IP |
| fwd_packet_length_min       | Smallest packet (bytes) send from source IP to destination IP |
| fwd_packet_length_mean      | The average size (bytes) of backets send from source IP to destination IP |
| fwd_packet_length_std       | The standard deviation of sizes of packets send from source IP to destination IP |
| bwd_packet_length_max       | Largest packet (bytes) send from destination IP to source IP |
| bwd_packet_length_min       | Smallest packet (bytes) send from destination IP to source IP |
| bwd_packet_length_mean      | The average size (bytes) of backets send from destination IP to source IP |
| bwd_packet_length_std       | The standard deviation of sizes of packets send from destination IP to source IP |
| flow_bytes_s                | The ratio of the total no. of bytes exchanged between destination IP and source IP to time in seconds |'
| flow_packets_s              | The ratio of the total no. of packets exchanged between destination IP and source IP to time in seconds |'
| flow_iat_mean               | The average Inter Arrival Times |
| flow_iat_std                | The standard deviation of all Inter Arrival Times |
| flow_iat_max                | The longest Inter Arrival Time |
| flow_iat_min                | The shortest Inter Arrival Time |
| fwd_iat_total               | The total Inter Arrival Time for packets send from source IP to destination IP |
| fwd_iat_mean                | The average Inter Arrival Time for packets send from source IP to destination IP |
| fwd_iat_std                 | The standard deviation for all Inter Arrival Times for packets send from source IP to destination IP |
| fwd_iat_max                 | The longest Inter Arrival Time for packets send from source IP to destination IP |
| fwd_iat_min                 | The shortest Inter Arrival Time for packets send from source IP to destination IP |
| bwd_iat_total               | The total Inter Arrival Time for packets send from destination IP to source IP |
| bwd_iat_mean                | The average Inter Arrival Time for packets send from destination IP to source IP |
| bwd_iat_std                 | The standard deviation for all Inter Arrival Times for packets send from destination IP to source IP |'
| bwd_iat_max                 | The longest Inter Arrival Time for packets send from destination IP to source IP |
| bwd_iat_min                 | The shortest Inter Arrival Time for packets send from destination IP to source IP |
| fwd_psh_flags               | No. of PSH TCP packets send from source IP to destination IP |
| bwd_psh_flags               | No. of PSH TCP packets send from destination IP to source IP |
| fwd_urg_flags               | No. of URG TCP packets send from source IP to destination IP |
| bwd_urg_flags               | No. of URG TCP packets send from destination IP to source IP |
| fwd_header_length           | Total size (bytes) of packet headers send from source IP to destination IP |
| bwd_header_length           | Total size (bytes) of segments send from destination IP to source IP |
| fwd_packets_s               | The ratio of the total no. of packets send from destination IP to source IP to time in seconds |
| bwd_packets_s               | The ratio of the total no. of packets  send from destination IP to source IP to time in seconds |
| min_packet_length           | Minimum size (bytes) of packet payload send |
| max_packet_length           | Maximum size(bytes) of packet payload send |
| packet_length_mean          | Average size of packet (bytes) |
| packet_length_std           | Standard deviation of all packet sizes |
| packet_length_variance      | Variance of all packet sizes |
| fin_flag_count              | No. of FIN TCP packets exchanged |
| syn_flag_count              | No. of SYN TCP packets exchanged |
| rst_flag_count              | No. of RST TCP packets exchanged |
| psh_flag_count              | No. of PSH TCP packets exchanged |
| ack_flag_count              | No. of ACK TCP packets exchanged |
| urg_flag_count              | No. of URG TCP packets exchanged |
| cwe_flag_count              | No. of CWE TCP packets exchanged |
| ece_flag_count              | No. of URG TCP packets exchanged |
| down_up_ratio               | Ratio of no. of backward packets to no. of forward packets |
| average_packet_size         | Average packet size (bytes) |
| avg_fwd_segment_size        | Average size (bytes) of packet headers send from source IP to destination IP |
| avg_bwd_segment_size        | Average size (bytes) of packet headers send from destination IP to source IP |
| fwd_avg_bytes_bulk          | Forward bulk average no. of bytes |
| fwd_avg_packets_bulk        | Forward bulk average no. of packets |
| fwd_avg_bulk_rate           | Forward average bulk rate |
| bwd_avg_bytes_bulk          | Backward bulk average no. of bytes |
| bwd_avg_packets_bulk        | Backward bulk average no. of packets |
| bwd_avg_bulk_rate           | Backward average bulk rate |
| subflow_fwd_packets         | Sub flow forward packets |
| subflow_bwd_packets         | Sub flow backward packets |
| subflow_fwd_bytes           | Sub flow forward bytes |
| subflow_bwd_bytes           | Sub flow backward bytes |
| init_win_bytes_backward     | Initial backward TCP Window size |
| init_win_bytes_forward      | Initial forward TCP Window size |
| act_data_pkt_fwd            | Active forward data packets |
| min_seg_size_forward        | Minimum forward header size |
| active_mean                 | Active mean |
| active_max                  | Active Max |
| active_min                  | Active Min |
| active_std                  | Active Std |
| idle_max                    | Idle Max |
| idle_mean                   | Average idle time |
| idle_std                    | Idle Std |
| idle_min                    | Idle Min |
