/* 
 * @author Tiago Alves Macambira
 * @version $Id: main.c,v 1.3 2004-01-15 03:05:20 tmacam Exp $
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

int get_next_packet_offset(struct half_stream *client, struct e2k_header_t* hdr)
{
	return client->offset +	EDONKEY_HEADER_SIZE -1  + hdr->packet_size;
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


void handle_e2k_packet(struct tcp_stream *a_tcp)
{
	struct e2k_header_t *hdr= NULL;
	
	(void*)hdr = (void*)a_tcp->client.data;
	
	if ( hdr->msg == EDONKEY_FILE_REQUEST_OPCODE){
		struct e2k_packet_file_request_t *file_req;
		(void *)file_req = (void *)hdr;
		print_hash("File request from",a_tcp, &(file_req->hash));
	}
}


void handle_state_wait_full_header(struct tcp_stream *a_tcp, conn_state_t *conn_state)
{
	struct e2k_header_t *hdr= NULL;
	struct half_stream *client = &a_tcp->client;

	//printf("wait_full_header\n");
	/* Have we got enought data to be able to read 
	 * a full header? */
	if ( (client->count - client->offset) < EDONKEY_HEADER_SIZE){
		/* not enought data, keep  buffer's data */
		nids_discard (a_tcp, 0);
	} else {
		/* Read header data */
		(void*)hdr = (void*)client->data;
		fprintf(stderr, "%s\t", address_str(a_tcp->addr));
		printf ("proto=0x%02x packet_size=%i msg_id=0x%02x\n",
				hdr->proto, hdr->packet_size, hdr->msg);
		/* Is the current packet a intersting one? */
		if (hdr->msg == EDONKEY_FILE_REQUEST_OPCODE) {
			printf("!!! Header FILE REQUEST !!!\n");
			/* Process the packet. Keep all data. */
			conn_state->state = wait_full_packet;
			nids_discard (a_tcp, 0);
		} else{
			conn_state->state= skip_full_packet;
			/*Calc next packet's offset */
			conn_state->next_packet_offset =
				get_next_packet_offset(client, hdr);
		}
	}
}


void handle_state_wait_full_packet(struct tcp_stream *a_tcp, conn_state_t *conn_state)
{
	struct e2k_header_t *hdr = NULL;
	struct half_stream *client = &a_tcp->client;
	(void*)hdr = (void*)client->data; /* Read header data */

	printf("### wait_full_packet ###\n");

	/* Have we got enought data? */
	if (client->count >= (get_next_packet_offset(client, hdr) -1 )){
		/* yes, we have */
		handle_e2k_packet(a_tcp);
		/* Since we are done with this packet,
		 * let's wait for the next packet header */
		conn_state->state= wait_full_header;
		conn_state->next_packet_offset = 
			get_next_packet_offset(client, hdr);
	} else {
		/*Not enought data? Keep the the one he already
		 * have and go get some more */
		nids_discard (a_tcp, 0);
		conn_state->state = wait_full_packet;
	}
}




void handle_state_skip_full_packet(struct tcp_stream *a_tcp, conn_state_t *conn_state)
{
	struct half_stream *client = &a_tcp->client;

	/* Have we reached the next packet? */
	if (client->count < conn_state->next_packet_offset){
		/* Nothing to be done - we still haven't 
		 * skiped the last packet... just keep
		 * going... */
		return;
	} else {
		/* We reached the next packet.
		 * Discard the last bytes of the last
		 * packet and get back to wait_full_header
		 * mode */
		nids_discard (a_tcp, conn_state->next_packet_offset - client->offset);
		conn_state->state= wait_full_header;
	}
}




void handle_tcp_data(struct tcp_stream *a_tcp, conn_state_t *conn_state)
{	
	switch(conn_state->state){
		case wait_full_header:
			handle_state_wait_full_header(a_tcp, conn_state);
			break;
		case wait_full_packet:
			handle_state_wait_full_packet(a_tcp, conn_state);
			break;
		case skip_full_packet:
			handle_state_skip_full_packet(a_tcp, conn_state);
			break;
	}
}



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
		/* Register state tracking data with the stream*/
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
	if (!nids_init()) {
		fprintf(stderr, "%s\n", nids_errbuf);
		exit(1);
	}
	nids_register_tcp(tcp_callback);
	nids_run();
	return 0;
}
