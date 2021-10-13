#include "secret.hpp"

// Define the Packet Constants
// ping packet size
#define PING_PKT_S 64
// Automatic port number
#define PING_SLEEP_RATE 1000000
// buffer size in bytes for reading from file
#define BUFFER_SIZE 16

// ping packet structure
struct ping_pkt {
    struct icmphdr hdr;
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
};


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

// make a ping request
void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_ip) {
    int msg_count=0;

    struct ping_pkt pckt;

    //filling packet
    char *message = "ahojahas";
    bzero(&pckt, sizeof(pckt));
    bcopy(message, &pckt.msg, strlen(message));
    printf("%s\n", pckt.msg);
    
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

void client_func(char *ip_addr) {
    int sockfd;
    struct sockaddr_in addr_con;

    addr_con.sin_family = AF_INET;
    addr_con.sin_addr.s_addr = inet_addr(ip_addr);
    addr_con.sin_port = 0;
    memset(&addr_con.sin_zero, 0, sizeof (addr_con.sin_zero));

    //socket()
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd<0) {
        printf("\nSocket file descriptor not received!!\n");
        exit(1);
    }
    else {
        printf("\nSocket file descriptor %d received\n", sockfd);
    }

    send_ping(sockfd, &addr_con, ip_addr);
}

int main(int argc, char *argv[]) {

    // if(argc!=2) {
    //     printf("\nFormat %s <address>\n", argv[0]);
    //     return 0;
    // }

    FILE *fptr;
    if ((fptr = fopen(argv[1], "rb")) == NULL) {
        printf("File %s loading failed!\n", argv[1]);
    }
    
    /* Get the number of bytes */
    fseek(fptr, 0L, SEEK_END);
    long file_numbytes = ftell(fptr);
    fseek(fptr, 0L, SEEK_SET);
    
    for (int i = 0; i <= file_numbytes; i++) {
        unsigned char buffer[BUFFER_SIZE+1] = {0};
        int count = fread(buffer, 1, BUFFER_SIZE, fptr);
        printf("Data read from file: %s \n", buffer);
        printf("Elements read: %d\n", count);
        i += BUFFER_SIZE;
    }
    
    fclose(fptr);

    
    char *ip_addr = argv[2];

    client_func(ip_addr);

    return 0;
}