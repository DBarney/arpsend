/*
 * fillin_settings()
 * is_dangerous_settings()
 * send_arp_packet()
 *
 * Copyright (c) 2001-2004, The Trustees of Princeton University, All Rights Reserved.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "defs.h"
#include "arpsend.h"

/* for libnet */
char libnet_errbuf[LIBNET_ERRBUF_SIZE];
libnet_t *l = NULL;

u_int8_t eaddr_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


/* Fill in settings, taking into account args and options.
   Also opens nd, the link interface.
*/
void 
fillin_settings(void)
{

	/* Initialize libnet context.  
	   If user didn't specify interface_name, allow libnet to select an interface.
	*/
	if ((l = libnet_init(LIBNET_LINK, interface_name, libnet_errbuf)) == NULL) {
			fprintf(stderr, "%s: error initializing libnet for interface '%s': %s", 
				prog, 
				interface_name ? interface_name : "(unspecified)", 
				libnet_errbuf);
			cleanup();
			exit(1);
	}

	/* Throw out the (possibly NULL) interface name that was requested, and grab the one libnet will use. 
	   This may be NULL without this being an error.
	   Note that in libnet 1.1.2.1, libnet_getdevice() returns int8_t*.
	*/
	interface_name = strdup((const char *) libnet_getdevice(l));

	if (!sender_protocol_address_set) {
		/* sender_protocol_address defaults to that of outgoing interface */
		/* Note libnet_get_ipaddr4() returns big-endian order, so no conversion to network byte order is needed. */
		if ((sender_protocol_address.s_addr = libnet_get_ipaddr4(l)) == -1) {
			fprintf(stderr, "%s: can't determine IP address of interface '%s': %s\n", prog, interface_name, libnet_geterror(l));
			cleanup();
			exit(1);
		}
	}

	if (!ether_source_address_set || !sender_hardware_address_set) {
		struct libnet_ether_addr *my_eaddr;

		/* set my_eaddr to that of the outgoing interface */
		if ((my_eaddr = libnet_get_hwaddr(l)) == NULL) {
			fprintf(stderr, "%s: can't determine hardware address of interface '%s': %s\n", prog, interface_name, libnet_geterror(l));
			cleanup();
			exit(1);
		}

		if (!ether_source_address_set) {
			bcopy(my_eaddr, &ether_source_address, sizeof(ether_source_address));
		}
		if (!sender_hardware_address_set) {
			bcopy(my_eaddr, &sender_hardware_address, sizeof(sender_hardware_address));
		}
	}

	if (!ether_dest_address_set) {
		/* ether_dest_address defaults to Ethernet broadcast address */
		bcopy(&eaddr_broadcast, &ether_dest_address.ether_addr_octet, sizeof(ether_dest_address.ether_addr_octet));
	}

	if (!target_hardware_address_set) {
		/* target_hardware_address defaults to 0 */
		bzero(&target_hardware_address, sizeof(target_hardware_address));
	}

	if (!arp_opcode_set) {
		/* arp_opcode defaults to ARPOP_REQUEST */
		arp_opcode = ARPOP_REQUEST;
	}

	
	if (!quiet) {
		fprintf(stdout, "Using settings:\n");
		fprintf(stdout, "  interface %s\n", interface_name);
		fprintf(stdout, "  ether_source_address %s\n", ether_ntoa((struct ether_addr *) &ether_source_address));
		fprintf(stdout, "  ether_dest_address %s\n", ether_ntoa((struct ether_addr *) &ether_dest_address));
		if (use_8021q) {
			fprintf(stdout, "  802.1q VLAN ID %d\n", vlan_id);
		}
		fprintf(stdout, "  arp_opcode %u (%s)\n", arp_opcode,
				arp_opcode==ARPOP_REQUEST ? "request" : (arp_opcode == ARPOP_REPLY ? "reply" : "unknown"));
		fprintf(stdout, "  sender_hardware_address %s\n", ether_ntoa((struct ether_addr *) &sender_hardware_address));
		fprintf(stdout, "  sender_protocol_address %s\n", inet_ntoa(sender_protocol_address));
		fprintf(stdout, "  target_hardware_address %s\n", ether_ntoa((struct ether_addr *) &target_hardware_address));
		fprintf(stdout, "  target_protocol_address %s\n", inet_ntoa(target_protocol_address));
	}
	
	return;
}


/* Check for dangerous settings; return 1 if any found, else return 0.
   Print a warning for each dangerous item found.
 */
int
is_dangerous_settings(void)
{
	int danger_found = 0;

	/* An ether_src should never be multicast or broadcast.
	   Imagine what happens if bridges/switches learn ff:ff:ff:ff:ff:ff is located on a specific port!
	*/
	if (ether_source_address.ether_addr_octet[0] & 0x01) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: ether_source_address '%s' is broadcast or multicast\n(not a valid Ethernet source).\n", 
			ether_ntoa((struct ether_addr *) &ether_source_address));
		fprintf(stdout, "A careless switch/bridge might mistakenly insert this into its\nforwarding table.\n");
		danger_found++;
	}

	/* sender_hardware_address shouldn't be multicast.  
	   Regardless of arp_opcode, listeners may glean (spa,sha) into their arp caches.
	   And if arp_opcode is request, clients may send respond packets to sender_hardware_address.
	*/
	if (sender_hardware_address.ether_addr_octet[0] & 0x01) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: sender_hardware_address '%s' is broadcast or multicast.\n", 
			ether_ntoa((struct ether_addr *) &sender_hardware_address));
		fprintf(stdout, "Recipients of the frame (ether_dest_address=%s) that glean the\n(sender_hardware_address,sender_protocol_address) tuple may be left with a bad\nARP cache entry for the sender_protocol_address (%s).\n", ether_ntoa((struct ether_addr *) &ether_dest_address), inet_ntoa(sender_protocol_address));
		if (arp_opcode == ARPOP_REQUEST) {
			fprintf(stdout, "Also, any recipients that respond to the ARP Request will send their responses\nto this Ethernet multicast/broadcast address.\n");
		}
		danger_found++;
	}

	if (IN_CLASSD(target_protocol_address.s_addr)) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: target_protocol_address '%s' is an IP multicast address.\n", inet_ntoa(target_protocol_address));
		danger_found++;
	}
	if (target_protocol_address.s_addr == INADDR_BROADCAST) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: target_protocol_address '%s' is the IP limited\nbroadcast address.\n", inet_ntoa(target_protocol_address));
		danger_found++;
	}
	if (IN_EXPERIMENTAL(target_protocol_address.s_addr)) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: target_protocol_address '%s' is an IP experimental (Class E) address.\n", inet_ntoa(target_protocol_address));
		danger_found++;
	}
	if (MY_IN_LOOPBACK(target_protocol_address.s_addr)) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: target_protocol_address '%s' is on the loopback network.\n", inet_ntoa(target_protocol_address));
		danger_found++;
	}
	/* XXX we should also check to see if target_protocol_address is any of the other flavors of IP broadcast
	   addresses valid on this network.  
	*/

	if (IN_CLASSD(sender_protocol_address.s_addr)) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: sender_protocol_address '%s' is an IP multicast address.\n", inet_ntoa(sender_protocol_address));
		fprintf(stdout, "Recipients of the frame (ether_dest_address=%s) that glean the\n(sender_hardware_address,sender_protocol_address) tuple may be left with a bad\nARP cache entry for the sender_protocol_address.\n", ether_ntoa((struct ether_addr *) &ether_dest_address));
		danger_found++;
	}
	if (sender_protocol_address.s_addr == INADDR_BROADCAST) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: sender_protocol_address '%s' is the IP limited\nbroadcast address.\n", inet_ntoa(sender_protocol_address));
		fprintf(stdout, "Recipients of the frame (ether_dest_address=%s) that glean the\n(sender_hardware_address, sender_protocol_address) tuple may be left with a bad\nARP cache entry for the IP limited broadcast address.\n", ether_ntoa((struct ether_addr *) &ether_dest_address));
		danger_found++;
	}
	if (IN_EXPERIMENTAL(sender_protocol_address.s_addr)) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: sender_protocol_address '%s' is an IP experimental (Class E) address.\n", inet_ntoa(sender_protocol_address));
		fprintf(stdout, "Recipients of the frame (ether_dest_address=%s) that glean the\n(sender_hardware_address,sender_protocol_address) tuple may be left with a bad\nARP cache entry for the sender_protocol_address.\n", ether_ntoa((struct ether_addr *) &ether_dest_address));
		danger_found++;
	}
	if (MY_IN_LOOPBACK(sender_protocol_address.s_addr)) {
		if (danger_found) /* this is not our first warning */
			fprintf(stdout, "\n");
		fprintf(stdout, "*** Warning: sender_protocol_address '%s' is on the loopback network.\n", inet_ntoa(sender_protocol_address));
		danger_found++;
	}
	/* XXX we should also check to see if sender_protocol_address is any of the other flavors of IP broadcast
	   addresses valid on this network.  
	*/
	

	{
		struct in_addr my_ipaddr;
		struct libnet_ether_addr *my_eaddr; /* XXX libnet_get_hwaddr() returns ptr to static storage */

		if (((my_eaddr = libnet_get_hwaddr(l)) != NULL) &&
			(((my_ipaddr.s_addr = libnet_get_ipaddr4(l))) != -1)) {

			/* we were able to determine my_eaddr and my_eaddr for this interface */
	
			if ((sender_protocol_address.s_addr == my_ipaddr.s_addr) && bcmp(&sender_hardware_address, my_eaddr, sizeof(my_eaddr))) {
				if (danger_found) /* this is not our first warning */
					fprintf(stdout, "\n");
				fprintf(stdout, "*** Warning: sender_protocol_address '%s' is my IP address, but\nsender_hardware_address '%s' ",
						inet_ntoa(sender_protocol_address), ether_ntoa((struct ether_addr *) &sender_hardware_address));
				/* ether_ntoa() returns static storage, break calls into separate statements */
				fprintf(stdout, "is not my Ethernet address\n('%s').\n", ether_ntoa((struct ether_addr *) my_eaddr));
				fprintf(stdout, "Recipients of the frame (ether_dest_address=%s) that glean the\n(sender_hardware_address,sender_protocol_address) tuple may be left with a bad\nARP cache entry for my IP address.\n", ether_ntoa((struct ether_addr *) &ether_dest_address));
				danger_found++;
			}
		}
	}
	
	return danger_found;
}


/* construct and send ARP packet.
   Return 0 on success, 1 on failure.
*/
int
send_arp_packet(void)
{
	int ether_arp_packet_size; /* size of packet we will write */
	int bytes_written;

	/* build the ARP header and payload */
	if (libnet_build_arp(
		ARPHRD_ETHER,									/* hardware type */
		ETHERTYPE_IP,									/* proto type */
		6,												/* haddr len, 6 == Ethernet */
		4,												/* proto len, 4 == IPv4 */
		arp_opcode,										/* arp_opcode == ARPOP_REQUEST or ARPOP_REPLY */
		sender_hardware_address.ether_addr_octet,		/* arp_sha */
		(u_int8_t *) &sender_protocol_address.s_addr,	/* arp_spa */
		target_hardware_address.ether_addr_octet,		/* arp_tha */
		(u_int8_t *) &target_protocol_address.s_addr,	/* arp_tpa */
		NULL, 0,										/* no optional payload */
		l,												/* libnet context */
		0												/* libnet protocol tag, 0 == build new one */
	) == -1) {
		fprintf(stderr, "%s: libnet_build_arp failed: %s\n", prog, libnet_geterror(l));
		libnet_clear_packet(l);
		return(0);
	}

	if (use_8021q) {
		ether_arp_packet_size = LIBNET_802_1Q_H + LIBNET_ARP_H;
	
		/* build the Ethernet 802.1q header */
		if (libnet_build_802_1q(
			ether_dest_address.ether_addr_octet,			/* ether_dst */
			ether_source_address.ether_addr_octet,			/* ether_src */
			ETHERTYPE_VLAN,									/* TPI */
			VLAN_PRIORITY,									/* priority (0-7) */
			VLAN_CFI_FLAG,									/* CFI flag */
			vlan_id,										/* VLAN ID  (0-4095) */
			ETHERTYPE_ARP,									/* 802.3 len or Ethernet Type II ethertype */
			NULL, 0,										/* no optional payload */
			l,												/* libnet context */
			0												/* libnet protocol tag, 0 == build new one */
		) == -1) {
			fprintf(stderr, "%s: libnet_build_802_1q failed: %s\n", prog, libnet_geterror(l));
			libnet_clear_packet(l);
			return(0);
		}
		
	} else {
		ether_arp_packet_size = LIBNET_ETH_H + LIBNET_ARP_H;

		/* build the Ethernet header */
		if (libnet_build_ethernet(
			ether_dest_address.ether_addr_octet,			/* ether_dst */
			ether_source_address.ether_addr_octet,			/* ether_src */
			ETHERTYPE_ARP,									/* ethertype */
			NULL, 0,										/* no optional payload */
			l,												/* libnet context */
			0												/* libnet protocol tag, 0 == build new one */
		) == -1) {
			fprintf(stderr, "%s: libnet_build_ethernet failed: %s\n", prog, libnet_geterror(l));
			libnet_clear_packet(l);
			return(0);
		}
	}


	/* write the packet */
	if ((bytes_written = libnet_write(l)) == -1 ) {
		fprintf(stderr, "%s: libnet_write failed: %s\n", prog, libnet_geterror(l));
		libnet_clear_packet(l);
		return(0);
	}
	if (bytes_written < ether_arp_packet_size)
		fprintf(stderr, "%s: libnet_write: bytes written: %d (expected %d)\n", prog, bytes_written, ether_arp_packet_size);

	libnet_clear_packet(l);
	return(1); /* success */
}
