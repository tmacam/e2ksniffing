/* 
 * @author Tiago Alves Macambira
 * @version $Id: main.c,v 1.4 2004-01-21 04:41:00 tmacam Exp $
 * 
 * 
 * Based on sample code provided with libnids and copyright (c) 1999
 * Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
 * See the file COPYING from libnids for license details.
 *
 * 
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "nids.h"

#include "main.h"
#include "e2k_defs.h"


/* ********************************************************************  
 *  Utility functions
 * ******************************************************************** */


/**@brief translates a tuple4 struct to a string
 *
 * struct tuple4 contains addresses and port numbers of the TCP connections
 * the following auxiliary function produces a string looking like
 * 10.0.0.1,1024,10.0.0.2,23
 *
 * The string is returned in a statically allocated buffer,  which
 * subsequent calls will overwrite.
 */
const char *address_str(struct tuple4 addr)
{
	static char buf[256];
	strncpy(buf, inet_ntoa(*((struct in_addr *)&(addr.saddr))), 256);
	snprintf(buf + strlen(buf), 256, ":%i, ", addr.source);
	strncpy(buf, inet_ntoa(*((struct in_addr *)&(addr.daddr))),256);
	snprintf(buf + strlen(buf), 256, ":%i", addr.dest);
	return buf;
}

/**@brief Prints a MD4 hash
 *
 * This function will print the hex-coded version of a given MD4 hash along
 * with some extra "identification" strings and the address
 * 
 * @param func_name the name of the "function". Since this function was used
 * mainly for "debuging" or "verbose output", there was a need to know
 * where the printed hash came from, from which "function", hence "func_name".
 * The contents of this string will be printed on the begining of the line
 *
 * @param a_tcp the "stream" whose address will be printed along "func_name"
 *
 * @param e2k_hash the MD4 hash
 */
void print_hash(char* func_name,struct tcp_stream *a_tcp,struct e2k_hash_t* hash )
{
	byte* hash_data = hash->data; /* Saving 16 ptrs. indirections*/
        printf("%s (%s) \tHash: '%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x'\n",
		func_name, 
		address_str(a_tcp->addr),
		hash_data[0], hash_data[1], hash_data[2], hash_data[3], 
		hash_data[4], hash_data[5], hash_data[6], hash_data[7],
		hash_data[8], hash_data[9], hash_data[10],hash_data[11],
		hash_data[12],hash_data[13],hash_data[14],hash_data[15]);
}


 
/* ********************************************************************  
 * edonkey protocol handling funtions
 * ******************************************************************** */

/**@brief Process a sniffed edonkey packet
 *
 * @param pkt_data the edonkey packet raw data
 * 
 * @param addr_tuple pointer to a structure with  addres/port of the
 * two endpoints of the connection from where the packet was sniffed.
 */
void handle_edonkey_packet(char *pkt_data/*, struct tuple4* addr_tuple*/)
{
	struct e2k_header_t *hdr= NULL;
	
	(void*)hdr = (void*)pkt_data;
	
	/*if ( hdr->msg == EDONKEY_FILE_REQUEST_OPCODE){
		struct e2k_packet_file_request_t *file_req;
		(void *)file_req = (void *)hdr;
		print_hash("File request from",a_tcp, &(file_req->hash));
	}*/
	printf ("E2K package > proto=0x%02x packet_size=%i msg_id=0x%02x\n",
			hdr->proto, hdr->packet_size, hdr->msg);
	
}


/* ********************************************************************  
 * edonkey state-machine control function
 * ******************************************************************** */

#define HANDLE_STATE_NEED_MORE_DATA -1
#define HANDLE_STATE_SUCCESSFUL 0
/**@brief Given the current position in the stream and the length of
 * the current edonkey packet, returns the position (offset) of the next packet.
 *
 * @param current_offset our current position in the stream
 * @param current_packet_len the length of the packet
 */
inline int get_next_packet_offset(int current_offset, int current_packet_len)
{
	return current_offset +	EDONKEY_HEADER_SIZE -1  + current_packet_len;
	/* -1 => hdr->msg (byte) is beeing counted
	 * twice, since packet_size includes the
	 * msg. header byte
	 * 
	 * +1 => but we want to reach the NEXT packet
	 * border... NEVERMIND, it starts counting on 0
	 *
	 * Let's just keep it for legibility sake's
	 *  - i won't remember it later anyway...
	 */
}

/**@brief
 *
 * Packet position is expected in conn_state->next_packet_offset
 *
 * @return 0 (zero) if the it successfuly completed it's intented function
 * with the available data; non-zero otherwise
 */
int handle_state_wait_full_header(struct tcp_stream *a_tcp, conn_state_t *conn_state)
{
	struct e2k_header_t *hdr= NULL;
	struct half_stream *client = &a_tcp->client;
	
	/* So, the next full donkey packet is how many bytes away from the
	 * start of client->data ? */
	int offset_shift = conn_state->next_packet_offset - client->offset;

	/* Have we got enough data to be able to read a full header? */
	if ( (client->count - conn_state->next_packet_offset) < EDONKEY_HEADER_SIZE){
		/* not enough data: keep current position and state;
		 * return w/ failure */
		return HANDLE_STATE_NEED_MORE_DATA;
	} else {
		/* Read header data */
		(void*)hdr = (void*)(client->data + offset_shift);
		fprintf(stderr, "%s\t", address_str(a_tcp->addr));
		printf ("Header > proto=0x%02x packet_size=%i msg_id=0x%02x\n",
				hdr->proto, hdr->packet_size, hdr->msg);
		/* Enough data - change state */
		conn_state->state = wait_full_packet;
		return HANDLE_STATE_SUCCESSFUL;
	}
}

/**@brief
 *
 * Packet position is expected in conn_state->next_packet_offset, i.e.,
 * as left from handle_state_wait_full_header
 *
 * @return 0 (zero) if the it successfuly completed it's intented function
 * with the available data; non-zero otherwise
 */
int handle_state_wait_full_packet(struct tcp_stream *a_tcp, conn_state_t *conn_state)
{
	char *pkt_data = NULL;
	struct e2k_header_t *hdr = NULL;
	struct half_stream *client = &a_tcp->client;

	/* The offset of the packet after the next*/
	int following_packet_offset = 0; 

	/* So, the next full donkey packet is how many bytes away from the
	 * start of client->data ? */
	int offset_shift = conn_state->next_packet_offset - client->offset;
	pkt_data = client->data + offset_shift;
	
	(void*)hdr = (void*)pkt_data; /* Read header data*/

	following_packet_offset = get_next_packet_offset(conn_state->next_packet_offset, hdr->packet_size);

	printf("### wait_full_packet ###\n");
	printf("count:%i, next -1:%i\n",client->count,(following_packet_offset-1 ) );
	
	/* Have we got enough data? */
	if ( client->count >= ( following_packet_offset - 1 ) ){
		/* yes, we have */
		handle_edonkey_packet(pkt_data);
		/* Since we are done with this packet,
		 * let's wait for the next packet header */
		conn_state->state= wait_full_header;
		conn_state->next_packet_offset = following_packet_offset;
		return HANDLE_STATE_SUCCESSFUL;
	} else {
		/* Not enough data? Keep current state and position,
		 * return with failure */
		return HANDLE_STATE_NEED_MORE_DATA;
	}
}



/**@brief
 *
 * @return 0 (zero) if the it successfuly completed it's intented function
 * with the available data; non-zero otherwise
 */
int handle_state_skip_full_packet(struct tcp_stream *a_tcp, conn_state_t *conn_state)
{
	struct half_stream *client = &a_tcp->client;

	/* Have we reached the next packet? */
	if (client->count < conn_state->next_packet_offset){
		/* Nothing to be done: we still haven't 
		 * skiped the last packet. Just keep
		 * the same state and position but wait for more data */
		return HANDLE_STATE_NEED_MORE_DATA;
	} else {
		/* We reached the next packet.
		 * Discard the last bytes of the last
		 * packet and get back to wait_full_header
		 * mode */
		conn_state->state= wait_full_header;
		return HANDLE_STATE_SUCCESSFUL;
	}
}




void handle_tcp_data(struct tcp_stream *a_tcp, conn_state_t *conn_state)
{	
	struct half_stream *client = &a_tcp->client;
	int need_more_data = 0;

	while (!need_more_data) {
		switch(conn_state->state){
			case wait_full_header:
				need_more_data = handle_state_wait_full_header(
						a_tcp,conn_state);
				break;
			case wait_full_packet:
				need_more_data = handle_state_wait_full_packet(
						a_tcp,conn_state);
				break;
			case skip_full_packet:
				need_more_data = handle_state_skip_full_packet(
						a_tcp,conn_state);
				break;
		}
	}
	/* Need more data. If the next packet is beyond the end of the
	 * current read data boundaries, discard everything. Else, save the
	 * begining of the next packet.
	 */
	if (client->count > conn_state->next_packet_offset)  {
		nids_discard(	a_tcp,	conn_state->next_packet_offset - a_tcp->client.offset);
	}
}


/* ********************************************************************  
 * Sniffing control functions
 * ******************************************************************** */

void tcp_callback(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	conn_state_t* conn_state = NULL;
	
	if (a_tcp->nids_state == NIDS_DATA) {
		/* new data has arrived in the client site */
		handle_tcp_data(a_tcp, *conn_state_ptr);
	} else	if (a_tcp->nids_state == NIDS_JUST_EST) {
		BEEN_HERE;
		/* connection described by a_tcp is established
		 * here we decide, if we wish to follow this stream
		 */
		if (a_tcp->addr.dest != EDONKEY_CLIENT_PORT) {
			return;
		}
		/* in this app we follow only the client requests */
		a_tcp->client.collect++; 
		//fprintf(stderr, "%s established\n",  address_str(a_tcp->addr));
		/* Alloc the state tracking structure */
		conn_state=(conn_state_t *)malloc(sizeof( conn_state_t));
		/* Setup state tracking structure*/
		conn_state->next_packet_offset = 0;
		conn_state->state = wait_full_header;
		/* Register/link state tracking data with the stream*/
		*conn_state_ptr = conn_state;
	} else if ( (a_tcp->nids_state == NIDS_CLOSE) ||
	     (a_tcp->nids_state == NIDS_RESET) ||
	     (a_tcp->nids_state == NIDS_TIMED_OUT) ){
		BEEN_HERE;
		/* free conn. related data */
		free(conn_state);
		*conn_state_ptr=NULL;
		/* connection has been closed normally */
		//fprintf(stderr, "%s closing\n",  address_str(a_tcp->addr));
		BEEN_HERE;
	};
	return;
}

int main()
{
	printf("Sniffing started.\n");
	// here we can alter libnids params, for instance:
	// nids_params.n_hosts=256;
	nids_params.device = "all";
	nids_params.one_loop_less = 0; /* We depend of this semantic */
	if (!nids_init()) {
		fprintf(stderr, "%s\n", nids_errbuf);
		exit(1);
	}

	/* FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME 
	 * 
	 * DROP PRIVILEGES !!!! 
	 * 
	 * FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME   */
	
	nids_register_tcp(tcp_callback);
	nids_run();
	return 0;
}
