/**@file e2k_state_machine.c
 * @brief edonkey state-machine control function
 * @author Tiago Alves Macambira
 * @version $Id: e2k_state_machine.c,v 1.4 2004-03-26 20:00:49 tmacam Exp $
 * 
 * 
 * Based on sample code provided with libnids and copyright (c) 1999
 * Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
 * See the file COPYING from libnids for license details.
 *
 *
 * (c) Tiago Alves Macambira
 * See COPYING for licence for further license details
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "nids.h"

#include "main.h"
#include "e2k_defs.h"
#include "e2k_proto.h"

#include "e2k_state_machine.h"


/* ******************************************************************** 
 * Module's Private Functions
 * ******************************************************************* */

/**@brief Verifies if a packet is "sane".
 *
 * Sane here means:
 * 	* It uses a known protocol in its header
 * 	* It is not larger then PACKET_MAXIMUM_SIZE
 *
 * @return (int as bool) 1 if packet is sane, 0 otherwise.
 */
inline int packet_is_sane(struct e2k_header_t* hdr)
{
	if ( // Is using a known protocol...
	     (  (hdr->proto == EDONKEY_PROTO_EDONKEY) ||
	        (hdr->proto == EDONKEY_PROTO_EMULE)  ) &&
	     // Is not stupidly large 
	     (hdr->packet_size < PACKET_MAXIMUM_SIZE)
	    ){
		return 1
	} else {
		return 0
	}
}

/* ******************************************************************** 
 * Module's Public Functions
 * ******************************************************************* */

int get_next_packet_offset(int current_offset, int current_packet_len)
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

int handle_state_wait_full_header(int is_server,
			    struct half_stream *halfstream,
			    half_conn_state_t *state)
{
	struct e2k_header_t *hdr= NULL;
	
	/* So, the next full donkey packet is how many bytes away from the
	 * start of halfstream->data ? */
	int offset_shift = state->next_packet_offset - halfstream->offset;

	/* Have we got enough data to be able to read a full header? */
	if ( (halfstream->count - state->next_packet_offset) <
	      EDONKEY_HEADER_SIZE){
		/* not enough data: keep current position and state;
		 * return w/ failure */
		return HANDLE_STATE_NEED_MORE_DATA;
	} else {
		/* Read header data */
		(void*)hdr = (void*)(halfstream->data + offset_shift);
		/* Don't we perl lovers/haters adore verbose outputs? */
		/*fprintf(stdout,"Header > %s proto=0x%02x packet_size=%i msg_id=0x%02x\n", state->connection->address_str, hdr->proto, hdr->packet_size, hdr->msg);*/
		/* Enough data - change state */
		if (state->blessed) {
			state->state = wait_full_packet;
			return HANDLE_STATE_SUCCESSFUL;
		} else {
			/* Unblessed. Does it seem like a edonkey conn.? */
			if ( ( (hdr->msg == EDONKEY_MSG_HELLO) ||
			       (hdr->msg == EDONKEY_MSG_HELLO_ANSWER) ) && 
			     ( (hdr->proto == EDONKEY_PROTO_EDONKEY) ||
			       (hdr->proto == EDONKEY_PROTO_EMULE) ) )
			{
				state->blessed = 1;
				state->state = wait_full_packet;
				return HANDLE_STATE_SUCCESSFUL;
			} else {
				/*We should ignore this bogus connection*/

				fprintf( stdout,"%s proto=0x%02x msg_id=0x%02x packet_size=%i BOGUS\n", state->connection->address_str, hdr->proto, hdr->msg, hdr->packet_size);
				conn_state_t* conn_state = state->connection;
				conn_state->client.state = ignore_connection;
				conn_state->server.state = ignore_connection;
				conn_state->ignore = 1;
				return HANDLE_STATE_NEED_MORE_DATA;
			}
		}
	}
}

int handle_state_wait_full_packet( int is_server,
			    struct half_stream *halfstream,
			    half_conn_state_t *state)
{
	char *pkt_data = NULL;
	struct e2k_header_t *hdr = NULL;

	/* The offset of the packet after the next*/
	int following_packet_offset = 0; 

	/* Access the header of the current packet */
	int offset_shift = state->next_packet_offset - halfstream->offset;
	pkt_data = halfstream->data + offset_shift;
	(void*)hdr = (void*)pkt_data; /* Read header data*/

	/* So, the next full donkey packet is how many bytes away from the
	 * start of halfstream->data ? */
	following_packet_offset = get_next_packet_offset(
					state->next_packet_offset,
					hdr->packet_size);

	/* Have we got enough data? */
	if ( halfstream->count >= (following_packet_offset - 1) ){
		/* yes, we have */
		handle_edonkey_packet(  is_server,
					pkt_data,
					state->connection->address_str);
		/* Since we are done with this packet,
		 * let's wait for the next packet header */
		state->state= wait_full_header;
		/* FIXME */
		assert(state->next_packet_offset < following_packet_offset);
		state->next_packet_offset = following_packet_offset;
		return HANDLE_STATE_SUCCESSFUL;
	} else {
		/* Not enough data? Keep current state and position,
		 * return with failure */
		return HANDLE_STATE_NEED_MORE_DATA;
	}
}



int handle_state_skip_full_packet(int is_server,
			    struct half_stream *halfstream,
			    half_conn_state_t *state)
{
	/* Have we reached the next packet? */
	if (halfstream->count < state->next_packet_offset){
		/* Nothing to be done: we still haven't 
		 * skiped the last packet. Just keep
		 * the same state and position but wait for more data */
		return HANDLE_STATE_NEED_MORE_DATA;
	} else {
		/* We reached the next packet.
		 * Discard the last bytes of the last
		 * packet and get back to wait_full_header
		 * mode */
		state->state = wait_full_header;
		return HANDLE_STATE_SUCCESSFUL;
	}
}

unsigned int handle_halfstream_data(int is_server,
			    struct half_stream *halfstream,
			    half_conn_state_t *state)
{	
	int need_more_data = 0;

	while (!need_more_data) {
		switch(state->state){
			case wait_full_header:
				need_more_data = handle_state_wait_full_header(
						is_server,halfstream,state);
				break;
			case wait_full_packet:
				need_more_data = handle_state_wait_full_packet(
						is_server,halfstream,state);
				break;
			case skip_full_packet:
				need_more_data = handle_state_skip_full_packet(
						is_server,halfstream,state);
				break;
			case ignore_connection:
				return 0; /* get out of HERE FAST!!! */
				break;
			default:
				/* HOW DID you GET here?! */
				abort();
		}
	}
	/* Need more data. If the next packet is beyond the end of the
	 * current read data boundaries, discard everything. Else, save the
	 * begining of the next packet.
	 */
	if (halfstream->count >= state->next_packet_offset)  {
		return (state->next_packet_offset - halfstream->offset);
	} else {
		return 0;
	}
}

