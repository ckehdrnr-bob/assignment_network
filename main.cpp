#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include<string.h>
#include<arpa/inet.h>
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
    /* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
    #define IP_RF 0x8000		/* reserved fragment flag */
    #define IP_DF 0x4000		/* dont fragment flag */
    #define IP_MF 0x2000		/* more fragments flag */
    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)		(((ip)->ip_vhl) >> 4)

    /* TCP header */
    typedef u_int tcp_seq;

    struct sniff_tcp {
        u_short th_sport;	/* source port */
        u_short th_dport;	/* destination port */
        tcp_seq th_seq;		/* sequence number */
        tcp_seq th_ack;		/* acknowledgement number */
        u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;		/* window */
        u_short th_sum;		/* checksum */
        u_short th_urp;		/* urgent pointer */
};
void print_ip(in_addr sip, in_addr dip ){
        printf("ip.sip = %s\n",inet_ntoa(sip));
        printf("ip.dip = %s\n",inet_ntoa(dip));

}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_macaddress(u_char *smac,u_char *dmac){
    printf("eht.smac = ");
    for(int i= 0; i<6;i++){
        printf("%02x",smac[i]);
        printf(":");
    }
    printf("\n");
    printf("eht.dmac = ");
    for(int i= 0; i<6;i++){
        printf("%02x",dmac[i]);
        printf(":");
    }
    printf("\n");

}
void print_tcpport(u_short sport,u_short dport){

    printf("tcp.sport = %d\n",ntohs(sport));
    printf("tcp.dport = %d\n",ntohs(dport));

}
int main(int argc, char* argv[]) {
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const u_char *payload; /* Packet payload */
    u_char *dd;
    int payload_size=0;

    u_int size_ip;
    u_int size_tcp;
    char eth_smac[6],eth_dmac[6];
    char  *ip_sip,*ip_dip; //inet_ntoa(strcut in_addr)
    u_int tcp_sport,tcp_dport;
    
    if (argc != 2) {
    usage();
    return -1;
  }
 //check arg
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);


    ethernet = (struct sniff_ethernet*)(packet);
  //  printf("%x\n",ntohs(ethernet->ether_type));
    if(ntohs(ethernet->ether_type)==0x0800)  {

        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    }else continue;

    size_ip = IP_HL(ip)*4;
    if(ip->ip_p ==6)tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    else continue;
    size_tcp = TH_OFF(tcp)*4;

    payload = packet + SIZE_ETHERNET + size_ip + size_tcp;

    printf("%u bytes captured\n", header->caplen);



    print_macaddress((u_char*)ethernet->ether_shost,(u_char*)ethernet->ether_dhost);

    print_ip(ip->ip_src,ip->ip_dst);

    print_tcpport(tcp->th_sport,tcp->th_dport);



     payload_size= header->caplen-SIZE_ETHERNET - size_ip - size_tcp;

     printf("tcp data = ");
     for(int i= 0; i<payload_size&&i<10 ; i++){
         printf("%02x ",payload[i]);
     }
    printf("\n\n");

  }

  pcap_close(handle);
  return 0;
}
