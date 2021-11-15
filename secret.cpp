#include "secret.hpp"

// Define the Packet Constants
// ping packet size
#define PING_PKT_SIZE 1392
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
const unsigned char *KEY = "xbelko02";
int FILE_SIZE = 0;
bool FIRST_PKT_CAME = false;
string FILE_NAME;
bool SECOND_PKT_CAME = false;


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


void send_ping(int ping_sockfd, struct addrinfo *ipinfo, unsigned char *encrypted_msg, int msg_size) {

    struct ping_pkt pckt;

    //filling packet
    bzero(&pckt, sizeof(pckt));
    bcopy(encrypted_msg, &pckt.msg, msg_size);
    
    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    //send packet
    if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) (ipinfo->ai_addr), ipinfo->ai_addrlen) <= 0) {
        printf("\nPacket Sending Failed!\n");
        exit(1);
    }
}


void client_func(char *filename, char* ip_addr) {

    struct addrinfo hints, *ipinfo;
    memset(&hints, 0, sizeof(hints));
    char *host = ip_addr;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    int res;
    if ((res = getaddrinfo(host, NULL, &hints, &ipinfo)) != 0) {
        fprintf(stderr, "%s\n", gai_strerror(res));
        exit(1);
    }

    int sockfd;
    int protocol = ipinfo->ai_family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
    //socket()
    sockfd = socket(ipinfo->ai_family, ipinfo->ai_socktype, protocol);
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

    string first_pkt = "firstpkt";
    first_pkt.append(to_string(file_numbytes));
    send_ping(sockfd, ipinfo, (unsigned char *) first_pkt.c_str(), first_pkt.size());
    if (!(icmp_reply)) {
        cerr << "Error: Echo Reply not received!" << endl;
        exit(1);
    }

    string second_pkt = "secondpk";
    second_pkt.append(basename(filename));
    send_ping(sockfd, ipinfo, (unsigned char *) second_pkt.c_str(), second_pkt.size());
    if (!(icmp_reply)) {
        cerr << "Error: Echo Reply not received!" << endl;
        exit(1);
    }

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
        AES_set_encrypt_key(KEY, 128, &encrypt_key);
        AES_encrypt((const unsigned char *) buffer, encrypted, &encrypt_key);

        for (int j = 0; j < BUFFER_SIZE; j++) {
            encrypted_msg[msg_offset] = encrypted[j];
            msg_offset++;
        }

        if (msg_offset >= (1384 - msg_tag_len)) {
            send_ping(sockfd, ipinfo, encrypted_msg, msg_offset);
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

    send_ping(sockfd, ipinfo, encrypted_msg, msg_offset);
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

	if (recvfrom(sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) &r_addr, &addr_len) <= 0) {
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
	    int header_size = sizeof(struct ethhdr) + 2 + iphdrlen + sizeof(icmph);

        if (((int) icmph->type) == 8) {

            const u_char *data = buffer + header_size;
            
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
            
            string first_pkt_tag = "firstpkt";
            if (!(strcmp((const char *) first_pkt_tag.c_str(), (const char *) pkt_msg_tag))) {
                FIRST_PKT_CAME = true;
                string first_pkt = (const char *) data;
                first_pkt.erase(0, 8);
                FILE_SIZE = stoi(first_pkt);
            }

            string second_pkt_tag = "secondpk";
            if (!(strcmp((const char *) second_pkt_tag.c_str(), (const char *) pkt_msg_tag))) {
                SECOND_PKT_CAME = true;
                string second_pkt = (const char *) data;
                second_pkt.erase(0, 8);
                FILE_NAME = second_pkt;
            }

            if (!(strcmp((const char *) msg_tag, (const char *) pkt_msg_tag)) && FIRST_PKT_CAME && SECOND_PKT_CAME) {

                AES_KEY decrypt_key;
                AES_set_decrypt_key(KEY, 128, &decrypt_key);
            
                if (FILE_SIZE < 1384) {
                    if (FILE_SIZE != 0) {
                        int data_size = FILE_SIZE;
                        FILE_SIZE = 0;
                        unsigned char decrypted_msg[data_size] = {0};
                        int msg_offset = 0;

                        int iterations = data_size / BUFFER_SIZE;

                        for (int i = 0; i < iterations; i++) {
                            unsigned char buffer[BUFFER_SIZE] = {0};

                            for (int j = 0; j < BUFFER_SIZE && data_offset < data_size; j++) {
                                buffer[j] = data[data_offset];
                                data_offset++;
                            }

                            unsigned char decrypted[BUFFER_SIZE] = {0};
                            AES_decrypt((const unsigned char *) buffer, decrypted, &decrypt_key);

                            for (int j = 0; j < BUFFER_SIZE && msg_offset < data_size; j++) {
                                decrypted_msg[msg_offset] = decrypted[j];
                                msg_offset++;
                            }
                        }

                        unsigned char buffer[BUFFER_SIZE] = {0};
                        for (int j = 0; j < BUFFER_SIZE; j++) {
                            buffer[j] = data[data_offset];
                            data_offset++;
                        }

                        unsigned char decrypted[BUFFER_SIZE] = {0};
                        AES_decrypt((const unsigned char *) buffer, decrypted, &decrypt_key);
                        
                        for (int j = 0; j < BUFFER_SIZE && msg_offset < data_size; j++) {
                            decrypted_msg[msg_offset] = decrypted[j];
                            msg_offset++;
                        }

                        FILE *fptr;
                        const char *filename = FILE_NAME.c_str();

                        if ((fptr = fopen(filename, "ab")) == NULL) {
                            printf("File %s opening failed!\n", filename);
                            exit(1);
                        }
                        fwrite(decrypted_msg, sizeof(unsigned char), data_size, fptr);

                        fclose(fptr);
                    }
                }
                else {
                    int data_size = 1384;
                    FILE_SIZE -= data_size;

                    unsigned char decrypted_msg[data_size] = {0};
                    int msg_offset = 0;

                    for (int i = 0; i + BUFFER_SIZE < data_size; i += BUFFER_SIZE) {
                        unsigned char buffer[BUFFER_SIZE] = {0};

                        for (int j = 0; j < BUFFER_SIZE && data_offset < data_size; j++) {
                            buffer[j] = data[data_offset];
                            data_offset++;
                        }

                        unsigned char decrypted[BUFFER_SIZE] = {0};
                        AES_decrypt((const unsigned char *) buffer, decrypted, &decrypt_key);

                        for (int j = 0; j < BUFFER_SIZE && msg_offset < data_size; j++) {
                            decrypted_msg[msg_offset] = decrypted[j];
                            msg_offset++;
                        }
                    }

                    FILE *fptr;
                    const char *filename = FILE_NAME.c_str();

                    if ((fptr = fopen(filename, "ab")) == NULL) {
                        printf("File %s opening failed!\n", filename);
                        exit(1);
                    }
                    fwrite(decrypted_msg, sizeof(unsigned char), data_size-8, fptr);

                    fclose(fptr);
                }
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
