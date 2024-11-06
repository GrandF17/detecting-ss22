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