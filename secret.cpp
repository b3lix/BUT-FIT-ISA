#include "secret.hpp"

// Define the Packet Constants
// ping packet size
#define PING_PKT_SIZE 1400
// Automatic port number
#define PING_SLEEP_RATE 1000000
// buffer size in bytes for reading from file
#define BUFFER_SIZE 16

// ping packet structure
struct ping_pkt {
    struct icmphdr hdr;
    char msg[PING_PKT_SIZE-sizeof(struct icmphdr)];
};

//key for encryption used by AES
const unsigned char *key = "xbelko02";


unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;
  
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_ip, unsigned char *encrypted_msg, int msg_size) {

    struct ping_pkt pckt;

    //filling packet
    bzero(&pckt, sizeof(pckt));
    bcopy(encrypted_msg, &pckt.msg, msg_size);
    
    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.id = getpid();

    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    //send packet
    if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0) {
        printf("\nPacket Sending Failed!\n");
        exit(1);
    }
}


void client_func(char *filename, char* ip_addr) {

    int sockfd;
    struct sockaddr_in addr_con;

    addr_con.sin_family = AF_INET;
    addr_con.sin_addr.s_addr = inet_addr(ip_addr);
    memset(&addr_con.sin_zero, 0, sizeof(addr_con.sin_zero));

    //socket()
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd<0) {
        printf("\nSocket file descriptor not received!!\n");
        exit(1);
    }
    else {
        printf("\nSocket file descriptor %d received\n", sockfd);
    }

    FILE *fptr;
    if ((fptr = fopen(filename, "rb")) == NULL) {
        printf("File %s loading failed!\n", filename);
        exit(1);
    }

    /* Get the number of bytes */
    fseek(fptr, 0L, SEEK_END);
    long file_numbytes = ftell(fptr);
    fseek(fptr, 0L, SEEK_SET);
    
    unsigned char encrypted_msg[PING_PKT_SIZE-sizeof(struct icmphdr)] = {0};
    int msg_tag_len = 8;
    unsigned char msg_tag[msg_tag_len] = "xbelko02";
    int msg_offset = 0;
    //copy msg tag
    for (int j = 0; j < msg_tag_len; j++) {
        encrypted_msg[msg_offset] = msg_tag[j];
        msg_offset++;
    }

    for (int i = 0; i < file_numbytes; i += BUFFER_SIZE) {
        unsigned char buffer[BUFFER_SIZE] = {0};
        int count = fread(buffer, 1, BUFFER_SIZE, fptr);

        unsigned char encrypted[BUFFER_SIZE] = {0};
        AES_KEY encrypt_key;
        AES_set_encrypt_key(key, 128, &encrypt_key);
        AES_encrypt((const unsigned char *) buffer, encrypted, &encrypt_key);

        unsigned char decrypted[BUFFER_SIZE] = {0};
        AES_KEY decrypt_key;
        AES_set_decrypt_key(key, 128, &decrypt_key);
        AES_decrypt((const unsigned char *) encrypted, decrypted, &decrypt_key);

        for (int j = 0; j < BUFFER_SIZE; j++) {
            encrypted_msg[msg_offset] = decrypted[j];
            msg_offset++;
        }

        if (msg_offset >= (1392 - msg_tag_len)) {
            send_ping(sockfd, &addr_con, ip_addr, encrypted_msg, msg_offset);
            if (!(icmp_reply)) {
                cerr << "Error: Echo Reply not received!" << endl;
                exit(1);
            }
            
            *encrypted_msg = {0};
            msg_offset = 0;
            for (int j = 0; j < msg_tag_len; j++) {
                encrypted_msg[msg_offset] = msg_tag[j];
                msg_offset++;
            }
            msg_offset = msg_tag_len;
        }
    }
    send_ping(sockfd, &addr_con, ip_addr, encrypted_msg, msg_offset);
    if (!(icmp_reply)) {
        cerr << "Error: Echo Reply not received!" << endl;
        exit(1);
    }

    fclose(fptr);
}

int icmp_reply(int sockfd) {
    struct sockaddr_in r_addr;
    struct ping_pkt pckt;

    //receive packet
	unsigned int addr_len=sizeof(r_addr);

	if (recvfrom(sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0) {
		printf("\nPacket receive failed!\n");
        return 0;
	}
	else {
        return 1;
	}
}

void server_func() {
    cout << "server" << endl;

    pcap_t *handle;
    char errbuf[100];

    handle = pcap_open_live(NULL, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
		fprintf(stderr, "Couldn't open device: %s\n", errbuf);
		exit(1);
	}
    pcap_loop(handle, -1, server_process_packet, NULL);
}

void server_process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
    int size = header->len;

    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr) + 2);
    
    if (iph->protocol == 1) {
        unsigned short iphdrlen;
        iphdrlen = iph->ihl * 4;

        struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr) + 2);
	    int header_size =  sizeof(struct ethhdr) + 2 + iphdrlen + sizeof(icmph);

        if (((int) icmph->type) == 8) {

            const u_char *data = buffer + header_size;
            int datalen = 136;
            int data_offset = 0;
            
            int msg_tag_len = 8;
            unsigned char msg_tag[msg_tag_len] = "xbelko02";

            unsigned char pkt_msg_tag[msg_tag_len] = {0};
            for (int j = 0; j < msg_tag_len; j++) {
                pkt_msg_tag[data_offset] = data[j];
                data_offset++;
            }
            //add null after string
            msg_tag[msg_tag_len] = 0;
            pkt_msg_tag[msg_tag_len] = 0;

            if (!(strcmp((const char *) msg_tag, (const char *) pkt_msg_tag))) {
                unsigned char decrypted_msg[datalen] = {0};
                int msg_offset = 0;

                for (int i = 0; i < datalen - msg_tag_len; i += BUFFER_SIZE) {
                    unsigned char buffer[BUFFER_SIZE] = {0};

                    for (int j = 0; j < BUFFER_SIZE && data_offset < datalen; j++) {
                        buffer[j] = data[data_offset];
                        data_offset++;
                    }

                    // unsigned char decrypted[BUFFER_SIZE] = {0};
                    // AES_KEY decrypt_key;
                    // AES_set_decrypt_key(key, 128, &decrypt_key);
                    // AES_decrypt((const unsigned char *) buffer, decrypted, &decrypt_key);

                    for (int j = 0; j < BUFFER_SIZE && msg_offset < datalen; j++) {
                        decrypted_msg[msg_offset] = buffer[j];
                        msg_offset++;
                    }
                }

                FILE *fptr;
                char *filename = "pixel.png";

                if ((fptr = fopen(filename, "ab")) == NULL) {
                    printf("File %s opening failed!\n", filename);
                    exit(1);
                }

                fwrite(decrypted_msg, sizeof(unsigned char), 119, fptr);

                fclose(fptr);
            }
        }
    }
}


int main(int argc, char *argv[]) {

    int opt;
    char *optstr = "r:s:l";
    char *filename, *ip_addr;
    bool server_mode = false;

    while ((opt = getopt(argc, argv, optstr)) != EOF) {
        switch (opt) {
        case 'r':
            filename = optarg;
            break;
        case 's':
            ip_addr = optarg;
            break;
        case 'l':
            server_mode = true;
            break;
        default:
            cerr << "help" <<  endl;
            exit(1);
            break;
        }
    }

    if (server_mode) {
        server_func();
    }
    else {
        client_func(filename, ip_addr);
    }

    return 0;
}
