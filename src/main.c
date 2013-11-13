/* arpsen_:
    Send an ARP Request containing fields specified by user.
    This is a diagnostic tool for use by a network administrator.

  Copyright (c) 2000-2006, The Trustees of Princeton University, All Rights Reserved.
*/



#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "defs.h"
#include "arpsend.h"
#include "utils.h"

#ifndef lint
static const char rcsid[] = "arpsend version " VERSION;
static const char copyright[] = "Copyright 2000-2006, The Trustees of Princeton University.  All rights reserved.";
static const char contact[] = "networking at princeton dot edu";
#endif

/* options, args, etc. */
char *prog;
int debug = 0;
int suppress_warnings = 0;
int quiet = 0;
int count = 1;
unsigned int pause_time = 1;

char *interface_name = NULL;
struct libnet_ether_addr ether_source_address;
struct libnet_ether_addr ether_dest_address;
struct libnet_ether_addr sender_hardware_address;
struct libnet_ether_addr target_hardware_address;
struct in_addr sender_protocol_address;
struct in_addr target_protocol_address;
u_short arp_opcode;
int ether_source_address_set = 0;
int ether_dest_address_set = 0;
int sender_hardware_address_set = 0;
int target_hardware_address_set = 0;
int sender_protocol_address_set = 0;
int target_protocol_address_set = 0;
int arp_opcode_set = 0;
int use_8021q = 0;
int vlan_id = 0;



int 
main(int argc, char **argv)
{
	/* for getopt() option and arg parsing */
	int c, errflag = 0;
	extern char *optarg;
	extern int optind, opterr, optopt;

	int do_send_packet;

	/* get progname = last component of argv[0] */
	prog = strrchr(argv[0], '/');
	if (prog)
		prog++;
	else 
		prog = argv[0];

	while ((c = getopt(argc, argv, "c:d:E:e:hi:o:p:Q:qS:s:T:t:vw")) != EOF) {
		switch (c) {
			
			case 'c': {
				char *stmp = optarg;
				if ((sscanf(stmp, "%d", &count) != 1) || (count < 1)) {
					fprintf(stderr, "%s: invalid packet count '%s', must be integer > 0\n", prog, optarg);
					count = 1;
					errflag++;
				}
				break;
			}

			case 'd': {
				char *stmp = optarg;
				if ((sscanf(stmp, "%d", &debug) != 1) || (debug < 0)) {
					fprintf(stderr, "%s: invalid debug level '%s'\n", prog, optarg);
					debug = 0;
					errflag++;
				}
				break;
			}

			case 'E': {
				struct libnet_ether_addr *eaddr_tmp;
				if ((eaddr_tmp = (struct libnet_ether_addr *) ether_aton(optarg)) == NULL) {
					fprintf(stderr, "%s: invalid ether_source_address '%s'\n", prog, optarg);
					errflag++;
				} else { 
					bcopy(&eaddr_tmp->ether_addr_octet, ether_source_address.ether_addr_octet, sizeof(ether_source_address.ether_addr_octet));
					ether_source_address_set++;
				}
				break;
			}

			case 'e': {
				struct libnet_ether_addr *eaddr_tmp;
				if ((eaddr_tmp = (struct libnet_ether_addr *) ether_aton(optarg)) == NULL) {
					fprintf(stderr, "%s: invalid ether_dest_address '%s'\n", prog, optarg);
					errflag++;
				} else { 
					bcopy(&eaddr_tmp->ether_addr_octet, ether_dest_address.ether_addr_octet, sizeof(ether_dest_address.ether_addr_octet));
					ether_dest_address_set++;
				}
				break;
			}

			case 'h':
				usage();
				exit(0);

			case 'i':
				interface_name = optarg;
				break;

			case 'o': {
				char *stmp = optarg;
				if (sscanf(stmp, "%hu", &arp_opcode) != 1) {
					fprintf(stderr, "%s: invalid arp_opcode '%s'\n", prog, optarg);
					arp_opcode = 0;
					errflag++;
				} else if ((arp_opcode != ARPOP_REQUEST) && (arp_opcode != ARPOP_REPLY)) {
					fprintf(stderr, "%s: invalid arp_opcode '%s',", prog, optarg);
					fprintf(stderr, " valid values are %u (ARPOP_REQUEST) and %u (ARPOP_REPLY)\n", ARPOP_REQUEST, ARPOP_REPLY);
					arp_opcode = 0;
					errflag++;
				}
				else
					arp_opcode_set++;
				break;
			}

			case 'p': {
				char *stmp = optarg;
				if (sscanf(stmp, "%u", &pause_time) != 1) {
					/* no need to ensure pause_time >= 0, as its unsigned. */
					fprintf(stderr, "%s: invalid pause_time '%s', must be integer >= 0\n", prog, optarg);
					pause_time = 1;
					errflag++;
				}
				break;
			}

			case 'Q': {
				char *stmp = optarg;
				if ((sscanf(stmp, "%d", &vlan_id) != 1) || (vlan_id < VLAN_ID_MIN) || (vlan_id > VLAN_ID_MAX)) {
					fprintf(stderr, "%s: invalid vlan ID '%s', must be integer %d ... %d\n", prog, optarg, VLAN_ID_MIN, VLAN_ID_MAX);
					errflag++;
				} else {
					use_8021q++;
				}
				break;
			}

			case 'q':
				quiet++;
				break;

			case 'S': {
				struct ether_addr *eaddr_tmp;
				if ((eaddr_tmp = ether_aton(optarg)) == NULL) {
					fprintf(stderr, "%s: invalid sender_hardware_address '%s'\n", prog, optarg);
					errflag++;
				} else { 
					bcopy(&eaddr_tmp->ether_addr_octet, sender_hardware_address.ether_addr_octet, sizeof(sender_hardware_address.ether_addr_octet));
					sender_hardware_address_set++;
				}
				break;
			}

			case 's':
				if (inet_aton(optarg, &sender_protocol_address) == 0) {
					fprintf(stderr, "%s: invalid sender_protocol_address '%s'\n", prog, optarg);
					errflag++;
				} else {
					sender_protocol_address_set++;
				}
				break;

			case 'T': {
				struct ether_addr *eaddr_tmp;
				if ((eaddr_tmp = ether_aton(optarg)) == NULL) {
					fprintf(stderr, "%s: invalid target_hardware_address '%s'\n", prog, optarg);
					errflag++;
				} else { 
					bcopy(&eaddr_tmp->ether_addr_octet, target_hardware_address.ether_addr_octet, sizeof(target_hardware_address.ether_addr_octet));
					target_hardware_address_set++;
				}
				break;
			}

			case 't':
				if (inet_aton(optarg, &target_protocol_address) == 0) {
					fprintf(stderr, "%s: invalid target_protocol_address '%s'\n", prog, optarg);
					errflag++;
				} else {
					target_protocol_address_set++;
				}
				break;

			case 'v':
				printf("arpsend version %s\n", VERSION);
				exit(0);

			case 'w':
				suppress_warnings++;
				break;

			case '?':
				usage();
				exit(0);

			default:
				errflag++;
				break;

		} /* switch (c) */
	} /* while c=getopt() */

	/* a valid target_protocol_address option is actually required */
	if (!target_protocol_address_set) {
		fprintf(stderr, "%s: target_protocol_address is required\n", prog);
		errflag++;
	}

	if (errflag) {
		if (!quiet) {
			fprintf(stderr, "\n"); /* separate error message we've already printed from usage message */
			usage();
		}
		exit(1);
	}

	/* we're done parsing commandline opts and args */

	/* fill in settings, taking into account commandline opts and args */
	fillin_settings();
	
	/* if we're allowed to warn about dangerous settings (warnings aren't suppressed)
	   and the settings are actually dangerous,
	   then prompt to see if we should still send the packet
	*/
	do_send_packet = 1; /* default to send */
	if (!suppress_warnings && is_dangerous_settings())
		do_send_packet = send_packet_prompt();


	if (do_send_packet) {
		while (count--) {
			if (send_arp_packet()) {
				/* the send succeeded */
				if (!quiet)
					fprintf(stdout, "packet sent\n");
			}
			if (count) { /* there are more packets to send */
				if (pause > 0)
					sleep(pause_time);
			}
		}
	} else
		fprintf(stdout, "send cancelled\n");

	cleanup();
	exit(0);
}


/* prompt if we should send the packet (default 'no').
   Return 1 for yes, 0 for no.
*/
int
send_packet_prompt(void)
{
	char buf[MAXLINE], response[MAXLINE];

	/* preceed prompt with newline since we must have printed some warning(s) earlier */
	fprintf(stdout, "\nSend anyway? [no] ");

	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		/* newline, EOF, or error */
		return 0; /* cancel sending packet */
	}
	response[0] = '\0';
	if (sscanf(buf, "%s", response) < 1) {
		/* newline, EOF, or error */
		return 0; /* cancel sending packet */
	}
	if ((response[0] == 'y') || (response[0] == 'Y'))
		return 1; /* send packet */
	else
		return 0; /* cancel sending packet */
}


/* cleanup tasks at exit */
void
cleanup(void)
{

	if (l) {
		libnet_destroy(l);
	}
	return;
}


/* print usage message and return */
void
usage(void)
{

	char *usage= "Usage: ";
	char *usage_and_progname;
	int usage_and_progname_len;

	/* build beginning of the usage message */
	usage_and_progname_len = strlen(usage) + strlen(prog) +1; /* 1 = trailing space */
	usage_and_progname = (char *) smalloc(usage_and_progname_len +1, 0); /* 1 = trailing NUL */
	snprintf(usage_and_progname, usage_and_progname_len+1, "%s%s ", usage, prog);

	fprintf(stderr, "%s", usage_and_progname);
	fprintf(stderr, "[-c count] [-d debuglevel] [-h] [-p pause_time] [-q] [-v] [-w]\n");
	fprintf(stderr, "%*s[-i interface_name]\n", usage_and_progname_len, "");
	fprintf(stderr, "%*s[-E ether_source_address]    [-e ether_dest_address] [-Q vlan_id]\n", usage_and_progname_len, "");
	fprintf(stderr, "%*s[-o arp_opcode]\n", usage_and_progname_len, "");
	fprintf(stderr, "%*s[-S sender_hardware_address] [-T target_hardware_address]\n", usage_and_progname_len, "");
	fprintf(stderr, "%*s[-s sender_protocol_address]  -t target_protocol_address\n", usage_and_progname_len, "");

	free(usage_and_progname);

	fprintf(stderr, "where:\n");
	fprintf(stderr, "   -c count                       count of packets to send (defaults to 1)\n");
	fprintf(stderr, "   -d debuglevel                  enable debugging at specified level (not presently used)\n");
	fprintf(stderr, "   -h                             display this help message then exit\n");
	fprintf(stderr, "   -p pause_time                  seconds to pause between sending each packet when count > 1 (defaults to 1)\n");
	fprintf(stderr, "   -q                             quiet output\n");
	fprintf(stderr, "   -v                             display version number then exit\n");
	fprintf(stderr, "   -w                             suppress warnings/prompt regarding dangerous settings\n");
	fprintf(stderr, "   -i interface_name              specify outgoing interface\n");
	fprintf(stderr, "   -E ether_source_address        override Ethernet frame source address (defaults to outgoing interface)\n");
	fprintf(stderr, "   -e ether_dest_address          override Ethernet frame dest address (defaults to ff:ff:ff:ff:ff:ff)\n");
	fprintf(stderr, "   -o arp_opcode                  override ARP opcode (defaults to 1 (request))\n");
	fprintf(stderr, "   -Q vlan_id                     tag the frame with an 802.1Q VLAN ID\n");
	fprintf(stderr, "   -S sender_hardware_address     override ARP Request sender hardware address (defaults to outgoing interface)\n");
	fprintf(stderr, "   -s sender_protocol_address     override ARP Request sender protocol address (defaults to outgoing interface)\n");
	fprintf(stderr, "   -T target_hardware_address     override ARP Request target hardware address (defaults to 0:0:0:0:0:0)\n");
	fprintf(stderr, "   -t target_protocol_address     specify ARP Request target protocol address (required)\n");

	return;
}
