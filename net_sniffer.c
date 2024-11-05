#include <math.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "./modules/entropy.c"

const size_t DEVICES_AMOUNT = 1;
const size_t PACKETS_AMOUNT = 10;

// =========================================
// variables we will write down to csv file:
size_t min_packet_size;
size_t max_packet_size;
double standard_deviation;
double entropy;

// ==================
// service variables:

// entropy
size_t empty_bits;
size_t filled_bits;

// standard_deviation
size_t packet_sizes[PACKETS_AMOUNT];
size_t packet_count;

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    // for standart packet len deviation:
    packet_sizes[packet_count] = header->len;
    ++packet_count;

    // min packet len
    if (min_packet_size == 0) {
        min_packet_size = header->len;
    } else {
        min_packet_size =
            min_packet_size < header->len ? min_packet_size : header->len;
    }

    // max packet len
    if (max_packet_size == 0) {
        max_packet_size = header->len;
    } else {
        max_packet_size =
            max_packet_size > header->len ? max_packet_size : header->len;
    }

    // entropy
    for (size_t i = 0; i < header->len; ++i) {
        empty_bits += 8 - bit_count_table[packet[i]];
        filled_bits += bit_count_table[packet[i]];
    }
}

void *listen_on_device(void *device_name) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live((char *)device_name, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open device %s: %s\n", (char *)device_name, error_buffer);
        return NULL;
    }

    /*while(1)*/ {
        // listen for 10 packets:
        printf("Listening on device: %s\n", (char *)device_name);
        pcap_loop(handle, 10, packet_handler, NULL);

        // counting entropy:
        entropy = count_bin_entropy(empty_bits, filled_bits);

        // counting standart packet len deviation:
        standard_deviation = count_deviation(packet_sizes, PACKETS_AMOUNT);

        printf("Minimum Packet Size: %zu bytesn", min_packet_size);
        printf("Maximum Packet Size: %zu bytesn", max_packet_size);
        printf("Packet Size Standard Deviation: %.4f bytesn", standard_deviation);
        printf("Packet Entropy: %.4f bytesn", entropy);
    }

    pcap_close(handle);
    return NULL;
}

int main() {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <client_ip> <server_ip>n", argv[0]);
        return 1;
    }

    char *client_ip = argv[1];
    char *server_ip = argv[2];

    // Создаем фильтр для захвата пакетов от клиента к серверу и от сервера к клиенту
    char filter_exp[200];
    snprintf(filter_exp, sizeof(filter_exp), "ip host %s and (ip dst %s or ip src %s)", client_ip, server_ip, server_ip);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Открываем интерфейс для захвата
    handle = pcap_open_live(INTERFACE1, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %sn", INTERFACE1, errbuf);
        return 1;
    }

    // Устанавливаем фильтр
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %sn", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %sn", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // devices:
    char devices[DEVICES_AMOUNT] = {/**"lo", */ "ens33"};
    pthread_t threads[DEVICES_AMOUNT];

    // threads for each device:
    for (int i = 0; i < DEVICES_AMOUNT; ++i) {
        if (pthread_create(&threads[i], NULL, listen_on_device, (void *)devices[i]) != 0) {
            fprintf(stderr, "Error creating thread for device %s\n", devices[i]);
            return 1;
        }
    }

    for (int i = 0; i < DEVICES_AMOUNT; ++i)
        pthread_join(threads[i], NULL);

    return 0;
}