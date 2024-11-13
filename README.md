### Unix compatible network sniffer

## To compile:
```bash
gcc net_sniffer.c ./libs/src/dynamic_double.c ./libs/src/dynamic_size_t.c ./libs/src/dynamic_flow_stats.c -o sniffer -lpcap -lm
```

## To run:
```bash
sudo ./sniffer <CLIENT_IP>
```

CSV file headers in canonical order:
```
// first TCP packet metrics:
entropy                 - 1-st TCP packet entropy 
correct_range_six       - TRUE if first 6 bytes are in range [0x20, 0x7e] (readable) 
correct_range_half      - TRUE if half of bytes is in range [0x20, 0x7e] (readable) 
correct_range_sequence  - TRUE if the are 20 bytes in a row in range [0x20, 0x7e] (readable) 
is_http_or_tls          - TRUE if sniffer has found TLS/HTTP proto mertics 

// other metrcis
total_time              - total session time in seconds
average_waiting_time    - total_time / amount_of_packets
client_pckt_amount      - amount of packets passed from client to server
server_pckt_amount      - amount of packets passed from server to client
min_packet_size
max_packet_size
packet_size_deviation    - standard deviation of packet lengths in a session
entropy                 - entropy of total flow per session
entropy_deviation       - standard deviation of packet entropy in a session
udp_lable               - just makes TRUE if met UDP in IP proto
tcp_lable               - just makes TRUE if met TCP in IP proto
sctp_lable              - just makes TRUE if met SCTP  in IP proto
tls_lable               - just makes TRUE if met some standart lables of TLS conncetion (too simple check)
ssh_lable               - just makes TRUE if met some standart lables of SSH conncetion (too simple check)
```

### Now sesions between two current IPs are divided by 5 seconds delay!!!
