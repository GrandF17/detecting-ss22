### Unix compatible network sniffer

## To compile:
```bash
gcc net_sniffer.c -o sniffer -lpcap -lm
```

## To run:
```bash
sudo ./sniffer <CLIENT_IP>
```

CSV file headers in canonical order:
```
total_time              - total session time in ms
average_waiting_time    - total_time / amount_of_packets
client_pckt_amount      - amount of packets passed from client to server
server_pckt_amount      - amount of packets passed from server to client
min_packet_size
max_packet_size
packet_len_deviation    - standard deviation of packet lengths in a session
entropy                 - entropy of total flow per session
entropy_deviation       - standard deviation of packet entropy in a session
udp_lable               - just makes TRUE if met UDP in IP proto
tcp_lable               - just makes TRUE if met TCP in IP proto
sctp_lable              - just makes TRUE if met SCTP  in IP proto
tls_lable               - just makes TRUE if met some standart lables of TLS conncetion (too simple check)
ssh_lable               - just makes TRUE if met some standart lables of SSH conncetion (too simple check)
```

###For now it is only 10 packets per session!!!