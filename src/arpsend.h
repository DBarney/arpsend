#ifndef ARPSEND_H
#define ARPSEND_H

/* options, etc. */
extern char *prog;
extern int debug;
extern int suppress_warnings;
extern int quiet;
extern int count;
extern unsigned int pause_time;

extern char *interface_name; 
extern struct libnet_ether_addr ether_source_address;
extern struct libnet_ether_addr ether_dest_address;
extern struct libnet_ether_addr sender_hardware_address;
extern struct libnet_ether_addr target_hardware_address;
extern struct in_addr sender_protocol_address;
extern struct in_addr target_protocol_address;
extern u_short arp_opcode;
extern int use_8021q;
extern int vlan_id;

/* flags indicating the user specified the value */
extern int ether_source_address_set;
extern int ether_dest_address_set;
extern int sender_hardware_address_set;
extern int target_hardware_address_set;
extern int sender_protocol_address_set;
extern int target_protocol_address_set;
extern int arp_opcode_set;


extern int sockfd; /* general purpose datagram socket fd for temp use throughout */

/* for libnet */
extern libnet_t *l;

#define MAXLINE 80

/* return 1 if i is on the loopback network */
#define MY_IN_LOOPBACK(i)  (((i) & 0xFF000000U) == 0x7F000000U)

#define VLAN_ID_MIN 0
#define VLAN_ID_MAX 4095
#define VLAN_PRIORITY 0x0
#define VLAN_CFI_FLAG 0x0

/* forward decls for functions */
void cleanup(void);
void usage(void);
void fillin_settings(void);
int is_dangerous_settings(void);
int send_arp_packet(void);
int send_packet_prompt(void);



#endif /* not ARPSEND_H */
