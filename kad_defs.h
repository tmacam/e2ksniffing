/**@file kad_defs.h
 * @brief Common kad definitions
 * @author Tiago Alves Macambira
 * @version $Id: kad_defs.h,v 1.1 2004-12-06 16:46:46 tmacam Exp $
 *
 * Some parts of this file are from ethereal's packet-edonkey.{c,h}, and
 * thus covered by it's own licence (GPL compat)
 *
 * Some parts od this file are from on eMule src. code and thus covered
 * by its own licence (GPL v2)
 * 
 * (c) Tiago Alves Macambira
 * See COPYING for licence for further license details
 *
 */

#ifndef _KAD_DEFS__H_
#define _KAD_DEFS__H_

#include "e2k_defs.h"


/* ********************************************************************  
 * Constants definition
 * ******************************************************************** */

// KADEMLIA (opcodes) (udp)
#define KADEMLIA_BOOTSTRAP_REQ	0x00	// <PEER (sender) [25]>
#define KADEMLIA_BOOTSTRAP_RES	0x08	// <CNT [2]> <PEER [25]>*(CNT)

#define KADEMLIA_HELLO_REQ	 	0x10	// <PEER (sender) [25]>
#define KADEMLIA_HELLO_RES     	0x18	// <PEER (receiver) [25]>

#define KADEMLIA_REQ		   	0x20	// <TYPE [1]> <HASH (target) [16]> <HASH (receiver) 16>
#define KADEMLIA_RES			0x28	// <HASH (target) [16]> <CNT> <PEER [25]>*(CNT)

#define KADEMLIA_SEARCH_REQ		0x30	// <HASH (key) [16]> <ext 0/1 [1]> <SEARCH_TREE>[ext]
#define KADEMLIA_SRC_NOTES_REQ	0x31	// <HASH (key) [16]> <ext 0/1 [1]> <SEARCH_TREE>[ext]
#define KADEMLIA_SEARCH_RES		0x38	// <HASH (key) [16]> <CNT1 [2]> (<HASH (answer) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)
#define KADEMLIA_SRC_NOTES_RES	0x39	// <HASH (key) [16]> <CNT1 [2]> (<HASH (answer) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)

#define KADEMLIA_PUBLISH_REQ	0x40	// <HASH (key) [16]> <CNT1 [2]> (<HASH (target) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)
#define KADEMLIA_PUB_NOTES_REQ	0x41	// <HASH (key) [16]> <CNT1 [2]> (<HASH (target) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)
#define KADEMLIA_PUBLISH_RES	0x48	// <HASH (key) [16]>
#define KADEMLIA_PUB_NOTES_RES	0x49	// <HASH (key) [16]>

#define KADEMLIA_FIREWALLED_REQ	0x50	// <TCPPORT (sender) [2]>
#define KADEMLIA_FINDBUDDY_REQ	0x51	// <TCPPORT (sender) [2]>
#define KADEMLIA_FINDSOURCE_REQ	0x52	// <TCPPORT (sender) [2]>
#define KADEMLIA_FIREWALLED_RES	0x58	// <IP (sender) [4]>
#define KADEMLIA_FIREWALLED_ACK	0x59	// (null)
#define KADEMLIA_FINDBUDDY_RES	0x5A	// <TCPPORT (sender) [2]>

// KADEMLIA (parameter)
#define KADEMLIA_FIND_VALUE		0x02
#define KADEMLIA_STORE			0x04
#define KADEMLIA_FIND_NODE		0x0B



/* ********************************************************************  
 * Protocol structures and typedefs 
 * ******************************************************************** */


struct kad_udp_peer_t{
	struct e2k_hash_t id;
	dword ip;
	word udp_port;
	word tcp_port;
	byte type;
}__attribute__ ((packed));

struct kad_udp_publish_entry_t{
	struct e2k_hash_t id;
	struct e2k_metalist_t metalist;
}__attribute__ ((packed));

struct kad_udp_packet_request_t{
	struct e2k_udp_header_t header;
	byte type;
	struct e2k_hash_t target;
	struct e2k_hash_t receiver;
}__attribute__ ((packed));

struct kad_udp_packet_response_t{
	struct e2k_udp_header_t header;
	struct e2k_hash_t target;
	byte count; /**< Number of found peers*/
	struct kad_udp_peer_t peers; /**< Found peers (use it as an array)*/
}__attribute__ ((packed));

struct kad_udp_packet_publish_res_t{
	struct e2k_udp_header_t header;
	struct e2k_hash_t file;
	byte load;
}__attribute__ ((packed));

struct kad_udp_packet_publish_req_t{
	struct e2k_udp_header_t header;
	struct e2k_hash_t target;
	byte count; /**< Number of entries in this publish request */
	/** entries (use it as an array) */
	struct kad_udp_publish_entry_t publish_entries; 
}__attribute__ ((packed));



#endif /* ifndef _KAD_DEFS__H_ */
