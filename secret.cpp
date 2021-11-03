#include "secret.hpp"

// Define the Packet Constants
// ping packet size
#define PING_PKT_S 1400
// Automatic port number
#define PING_SLEEP_RATE 1000000
// buffer size in bytes for reading from file
#define BUFFER_SIZE 16

// ping packet structure
struct ping_pkt {
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
};

//key for encryption used by AES
const unsigned char key[16] = {"xbelko020000000"};


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


void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_ip, unsigned char *encrypted_msg) {
    int msg_count=0;

    struct ping_pkt pckt;

    //filling packet
    bzero(&pckt, sizeof(pckt));
    bcopy(encrypted_msg, &pckt.msg, strlen((const char *) encrypted_msg));
    printf("Sent msg: %s\n", pckt.msg);
    
    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.id = getpid();

    pckt.hdr.un.echo.sequence = msg_count++;
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    //send packet
    if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0) {
        printf("\nPacket Sending Failed!\n");
        exit(1);
    }

    printf("Message count: %d\n", msg_count);
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
    
    unsigned char encrypted_msg[PING_PKT_S-sizeof(struct icmphdr)] = {0};
    int msg_offset = 0;
    for (int i = 0; i < file_numbytes; i++) {
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
        
        for (int j = 0; j < 16; j++) {
            encrypted_msg[msg_offset] = decrypted[j];
            msg_offset++;
        }

        if (msg_offset >= 1392) {
            send_ping(sockfd, &addr_con, ip_addr, encrypted_msg);
            *encrypted_msg = {0};
            msg_offset = 0;
        }

        i += BUFFER_SIZE;
    }
    send_ping(sockfd, &addr_con, ip_addr, encrypted_msg);

    fclose(fptr);
}


void server_func() {
    cout << "server" << endl;

    struct sockaddr_in r_addr;
    struct ping_pkt pckt;
    int sockfd;
    //socket()
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd<0) {
		printf("\nSocket file descriptor not received!!\n");
		exit(1);
	}
	else {
		printf("\nSocket file descriptor %d received\n", sockfd);
    }

    //receive packet
	int addr_len=sizeof(r_addr);

	if (recvfrom(sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0) {
		printf("\nPacket receive failed!\n");
	}
    // spravit to radsej cez pcap, netreba potom riesit ipv4 a ipv6 osobitne
	else {
		cout << "received: " << endl;
        cout << pckt.msg << endl;
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
