/* 
 * @author Tiago Alves Macambira
 * @version $Id: main.c,v 1.5 2004-01-21 06:27:36 tmacam Exp $
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
	strncpy(buf + strlen(buf), inet_ntoa(*((struct in_addr *)&(addr.daddr))),256);
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
 * @param addr_tuple the client and server addresses that will be printed
 * along "func_name"
 *
 * @param e2k_hash the MD4 hash
 */
void print_hash(char* func_name,struct tuple4* addr_tuple,struct e2k_hash_t* hash )
{
	byte* hash_data = hash->data; /* Saving 16 ptrs. indirections*/
        printf("%s (%s) \tHash: '%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x'\n",
		func_name, 
		address_str(*addr_tuple),
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
void handle_edonkey_packet(char *pkt_data, struct tuple4* addr_tuple)
{
	struct e2k_header_t *hdr= NULL;
	struct e2k_packet_file_request_t *file_req = NULL;
	
	(void*)hdr = (void*)pkt_data;
	(void *)file_req = (void *)pkt_data;
	
	if ( hdr->msg == EDONKEY_FILE_REQUEST_OPCODE){
		print_hash("File request from",addr_tuple, &(file_req->hash));
	} else if ( hdr->msg == EDONKEY_REQUEST_PARTS_OPCODE ){
		print_hash("Request parts from",addr_tuple, &(file_req->hash));
	}
#ifdef BE_VERBOSE
	fprintf( stdout,
		 "E2K pkt> %s proto=0x%02x packet_size=%i msg_id=0x%02x\n",
		 address_str(*addr_tuple), hdr->proto,
		 hdr->packet_size, hdr->msg);
#endif
	
}


/* ********************************************************************  
 * edonkey state-machine control function
 * ******************************************************************** */

#define HANDLE_STATE_NEED_MORE_DATA -1
#define HANDLE_STATE_SUCCESSFUL 0
/**@brief Given the current position in the stream and the length of
 * the current edonkey packet, returns the position (offset) of the next packet.
 *
 * @param current_offset our current position ( offset ) in the stream
 * @param current_packet_len the length of the packet
 *
 * @return the offset of the next packet
 */
inline int get_next_packet_offset(int current_offset, int current_packet_len)
{
	return current_offset +	EDONKEY_HEADER_SIZE -1  + current_packet_len;
	/* -1 => hdr->msg (byte) is beeing counted
	 * twice, since packet_size includes the
	 * msg. header byte
	 * 
	 * Let's just keep it for legibility sake's
	 *  - i won't remember it later anyway...
	 */
}

/**@brief State Machine - initial state
 *
 * This state will wait until we have enough data in the stream to read
 * a full donkey packet header ( aprox. 6 bytes, see EDONKEY_HEADER_SIZE ).
 * When it happens, it will pass the state machine to the next state - the
 * one that waits for a full packet.
 * 
 * Packet position is expected in conn_state->next_packet_offset, i.e, counting
 * from the start of the strem, the next packet will be offseted 
 * next_packet_offset bytes. If this offset was not reached yet,
 * we will keep waiting for more data.
 *
 * @warning next_packet_offset here means "the offset of the NEXT NOT FULLY
 * PROCESSED packet" in the stream.
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
#ifdef BE_VERBOSE
		/* Read header data */
		(void*)hdr = (void*)(client->data + offset_shift);
		/* Don't we perl lovers/haters adore verbose outputs? */
		fprintf(stdout,"Header > %s proto=0x%02x packet_size=%i msg_id=0x%02x\n", address_str(a_tcp->addr), hdr->proto, hdr->packet_size, hdr->msg);
#endif
		/* Enough data - change state */
		conn_state->state = wait_full_packet;
		return HANDLE_STATE_SUCCESSFUL;
	}
}

/**@brief  State Machine control - Waiting for a Full packet
 * 
 * So we have at least a complete donkey packet header available. With
 * it we can calc the size of the donkey packet we are currently reading
 * and thus we can manage to wait to gather enough bytes to assemble this
 * sniffed packet.
 * 
 * Packet position is expected in conn_state->next_packet_offset, i.e.,
 * as left from handle_state_wait_full_header, AND we expect that this 
 * position in the stream is accessible. Failing to assert these two conditions
 * may lead to unexpected behavior ( i.e., probably a crash / core dump ).
 *
 * If the packet is fully accessible in the stream, it will be passed for
 * further processing @ handle_edonkey_packet(), the next_packet_offset will
 * be updated to the offset of the next expected packet and the state machine
 * will be set to the default wait_full_header state. Otherwise we will keep
 * waiting for the full packet
 *
 * @warning this state SHOULD only be reache through wait_full_header
 * @warning next_packet_offset here means "the offset of the NEXT NOT FULLY
 * PROCESSED packet" in the stream.
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

	/* Have we got enough data? */
	if ( client->count >= ( following_packet_offset - 1 ) ){
		/* yes, we have */
		handle_edonkey_packet(pkt_data, &a_tcp->addr);
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



/**@brief State Machine - dumb state
 *
 * This state has no use currently. It should be used when we know we are not
 * interested in the next packet available in the stream ( whose position is
 * fiven by conn_state->next_packet_offset ) and we just want to skip it
 * and skip the full donkey packet processing functions.
 *
 * This function can be seen as a dumb ( and fast ) version of wait_full_packet.
 *
 * @warning Differently from the other 2 states, this function uses
 * next_packet_offset as the offset of the NEXT packet NOT SEEN yet in the
 * stream, not the the offset of the next unprocessed packet.
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



/**@brief Controls new data processing - state machine control loop
 *
 * Summing up: basic state machine control.
 *
 * We will "run through" all the availiable data in the buffer currently,
 * extracting all the availiable packets from it, until there's nothing
 * left to be processed or there's no enough data in the stream to fully
 * process a complete packet.
 *
 * The "extraction" is controled by a very simple state machine ( only
 * 2 states used ). State information is stored in conn_state and is controled
 * by the handle_state_* functions.
 *
 *
 * @see conn_state_t
 */
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
