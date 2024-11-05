### Unix compatible network sniffer

## To compile:
```bash
gcc net_sniffer.c -o sniffer -lpcap -lm -pthread
```

## To run:
```bash
sudo ./sniffer <CLIENT_IP> <SERVER_IP>
```