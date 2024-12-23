### Unix compatible network sniffer

## To compile:
```bash
gcc net_sniffer.c ./libs/src/dynamic_double.c ./libs/src/dynamic_size_t.c ./libs/src/dynamic_flow_stats.c -o sniffer -lpcap -lm -lwebsockets
```

## To run:
```bash
sudo ./sniffer <CLIENT_IP> <DELAY> <MODE>
```

MODE: collect, broadcast

DELAY: 1, 2, 3... (just number in seconds)

### "First TCP packet metrics" field was constructed according to chinese <a href="https://gfw.report/publications/usenixsecurity23/en/#6-understanding-the-blocking-strategies" target="_blank">researches</a>
CSV file headers in canonical order:
```
# first TCP packet metrics
entropy                 - 1-st TCP packet entropy 
range_of_six            - TRUE if first 6 bytes are in range            [0x20, 0x7e] (readable) 
range_of_half           - TRUE if half of bytes is in range             [0x20, 0x7e] (readable) 
range_seq               - TRUE if the are 20 bytes in a row in range    [0x20, 0x7e] (readable) 
is_http_or_tls          - TRUE if sniffer found TLS/HTTP proto mertics 

# statistical study of the session on 
# IQR, medians and outliers
# for entropy, size rows
entropy                 - entropy of total flow per session
std_pckt_size           - standard deviation of packet lengths in a session
q1_pckt_size            - 1-st quartile (or 25-th percent), it is a median value of left half in sorted array
q2_pckt_size            - 2-nd quartile (or 50-th percent), it is a median value of sorted array
q3_pckt_size            - 3-d quartile (or 75-th percent), it is a median value of right half in sorted array
iqr_pckt_size           - interquartile range (Q1 - Q3)
pckt_size_outliers_lb   - here we count lower bounds as Q1−1.5*IQR, and count amount of values that are lower than this bound
pckt_size_outliers_ub   - here we count upper bounds as Q3+1.5*IQR, and count amount of values that are higher than this bound

std_entropy             - standard deviation of packet entropy in a session
q1_entropy              - 1-st quartile (or 25-th percent), it is a median value of left half in sorted array
q2_entropy              - 2-nd quartile (or 50-th percent), it is a median value of sorted array
q3_entropy              - 3-d quartile (or 75-th percent), it is a median value of right half in sorted array
iqr_entropy             - interquartile range (Q1 - Q3)
entropy_outliers_lb     - here we count lower bounds as Q1−1.5*IQR, and count amount of values that are lower than this bound
entropy_outliers_ub     - here we count upper bounds as Q3+1.5*IQR, and count amount of values that are higher than this bound

# some IP and 6 Layer OSI protos:
udp_label               - TRUE if met UDP   in IP proto
tcp_label               - TRUE if met TCP   in IP proto
sctp_label              - TRUE if met SCTP  in IP proto
http_label              - TRUE if met some standart labels of HTTP connection (simple check)
tls_label               - TRUE if met some standart labels of TLS connection (simple check)
ssh_label               - TRUE if met some standart labels of SSH connection (simple check)

# other simple metrcis
total_time              - total session time in milliseconds
avg_waiting_time        - total_time / amount_of_packets
client_pckt_amount      - amount of packets passed from client to server
server_pckt_amount      - amount of packets passed from server to client
min_pckt_size
max_pckt_size
keep_alive_pckt_amount  - amount of packets of min size (keep-alive packets)
```

### You can split sessions between 2 current ips by selecting amount of seconds for delay (5 seconds for example)!!!


## NOTE
If you want to add your own metrics to handle search for "here you can INSERT" and paste your own logic/variables to handle by this app
