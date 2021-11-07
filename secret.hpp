#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <openssl/aes.h>
#include <iostream>
#include <pcap.h>
#include<net/ethernet.h>

using namespace std;

void server_process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_icmp_packet(const u_char * , int );
void PrintData (const u_char * , int);
int icmp_reply(int sockfd);