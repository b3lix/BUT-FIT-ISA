#include "secret.hpp"

// Define the Packet Constants
// ping packet size
#define PING_PKT_S 64
// Automatic port number
#define PING_SLEEP_RATE 1000000
// Gives the timeout delay for receiving packets
// in seconds
#define RECV_TIMEOUT 1

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
    int ttl_val=64, msg_count=0, i, flag=1;

    struct ping_pkt pckt;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    // set socket options at ip to TTL and value to 64,
    // change to what you want by setting ttl_val
    if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
        printf("\nSetting socket options to TTL failed!\n");
        exit(1);
    }
    else {
        printf("\nSocket set to TTL..\n");
    }

    // setting timeout of recv setting
    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof tv_out);

    //filling packet
    char *message = "ahojahasdfasfsagsojkapnspadnf";
    bzero(&pckt, sizeof(pckt));
    bcopy(message, &pckt.msg, strlen(message));
    printf("%s\n", pckt.msg);
    
    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.id = getpid();

    pckt.hdr.un.echo.sequence = msg_count++;
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    usleep(PING_SLEEP_RATE);

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
        return;
    }
    else {
        printf("\nSocket file descriptor %d received\n", sockfd);
    }

    //send pings continuously
    send_ping(sockfd, &addr_con, ip_addr);
}

int main(int argc, char *argv[]) {

    if(argc!=2) {
        printf("\nFormat %s <address>\n", argv[0]);
        return 0;
    }
    char *ip_addr = argv[1];

    client_func(ip_addr);

    return 0;
}