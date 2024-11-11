// printf("New packet:\n");
// for (int i = 0; i < header->len; i++) {
//     printf("%02x ", packet[i]);
//     if ((i + 1) % 16 == 0) printf("\n");
// }
// printf("\n");
// printf("\n");

// if(
//     strncmp(inet_ntoa(ip_header->ip_src), client_ip, ip_header->ip_id) == 0 &&
//     strncmp(inet_ntoa(ip_header->ip_dst), server_ip, ip_header->ip_id) == 0
// ) {
//     // printf("Src: %s\n", inet_ntoa(ip_header->ip_src));
//     // printf("Dst: %s\n", inet_ntoa(ip_header->ip_dst));
//     // printf("Client: %s\n", client_ip);
//     // printf("Server: %s\n", server_ip);
//     // printf("Header len: %d\n", ip_header->ip_id);

//     ++client_server_packets_amount[0];
// } else if(
//     strncmp(inet_ntoa(ip_header->ip_src), server_ip, ip_header->ip_id) == 0 &&
//     strncmp(inet_ntoa(ip_header->ip_dst), client_ip, ip_header->ip_id) == 0
// ) {
//     ++client_server_packets_amount[1];
// }

// for tcp:
// inet_ntoa(ip_header->ip_src), ntohs(tcp_header->source)
// inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->dest)
// for udp:
// struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header_length);
// inet_ntoa(ip_header->ip_src), ntohs(udp_header->source)
// inet_ntoa(ip_header->ip_dst), ntohs(udp_header->dest)

// pthread_t thread;
// if (pthread_create(&thread, NULL, listen_on_device, (void *)&args) != 0) {
//     fprintf(stderr, "Error creating thread for device %s\n", INTERFACE);
//     return 1;
// }

// pthread_join(thread, NULL);

//

// // counting entropy:
// entropy = count_bin_entropy(empty_bits, filled_bits);

// // counting standart packet len deviation:
// packet_size_deviation = count_deviation_generic(packet_sizes, PACKETS_AMOUNT);
// entropy_deviation = count_deviation_generic(packet_entropy, PACKETS_AMOUNT);

// printf("Minimum Packet Size: %zu bytes\n", min_packet_size);
// printf("Maximum Packet Size: %zu bytes\n", max_packet_size);
// printf("Packet Size Standard Deviation: %.4f bytes\n", packet_size_deviation);
// printf("Packet Entropy: %.4f\n", entropy);
// printf("Packet Entropy Deviation: %.4f\n", entropy_deviation);

// printf("Protocols detected: ");
// if (udp_lable) printf("udp ");
// if (tcp_lable) printf("tcp ");
// if (sctp_lable) printf("sctp ");
// if (ssh_lable) printf("ssh ");
// if (tls_lable) printf("tls ");
// printf("\n");

//

// printf("Source IP: %s\n", src_ip);
// printf("Destination IP: %s\n", dst_ip);
// printf("From: %s; to: %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));