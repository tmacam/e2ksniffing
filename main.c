/* 
 * @author Tiago Alves Macambira
 * @version $Id: main.c,v 1.1.1.1 2004-01-15 00:53:50 tmacam Exp $
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

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

/* #define BEEN_HERE do {printf("BEEN HERE: %03i\n",__LINE__);} while(0) */
#define BEEN_HERE do {} while(0)

#define EDONKEY_CLIENT_PORT 4662
#define EDONKEY_FILE_REQUEST_OPCODE 0x58

/** The size of <uchar proto><dword pkt_len><uchar msg_type>*/
#define EDONKEY_HEADER_SIZE 6
/**@brief In which state are we rearding the sniffing of a given stream? */
enum sniff_state { 
	/** We are waiting for enought data to read the next header*/
	wait_full_header,
	/** we are just skiping till the begining of the next header */
	skip_full_packet,
	/** we are waiting for enought data to read the next packet */
	wait_full_packet
};

/**@brief Records the state of the e2k sniffing state machine for a given
 * connection.*/
typedef struct conn_state_t {
	/** The state of the sniffing state machine*/
	enum sniff_state state;
	/** How many bytes away is the next packet in the stream */
	int next_packet_offset;
} conn_state_t;

typedef unsigned long dword;
typedef unsigned short word;
typedef unsigned char byte;

struct e2k_header_t {
	/** The type of the protocol */
	byte proto;
	dword packet_size;
	byte msg;
}__attribute__ ((packed));

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char *adres(struct tuple4 addr)
{
	static char buf[256];
	strcpy(buf, int_ntoa(addr.saddr));
	sprintf(buf + strlen(buf), ":%i, ", addr.source);
	strcat(buf, int_ntoa(addr.daddr));
	sprintf(buf + strlen(buf), ":%i", addr.dest);
	return buf;
}

void tcp_callback(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	char buf[1024];
	conn_state_t* conn_state = NULL;
	
	strcpy(buf, adres(a_tcp->addr));	// we put conn params into buf
	if (a_tcp->nids_state == NIDS_JUST_EST) {
		BEEN_HERE;
		/* connection described by a_tcp is established
		 * here we decide, if we wish to follow this stream
		 */
		if (a_tcp->addr.dest != EDONKEY_CLIENT_PORT) {
			return;
		}
		/* in this app we follow only the client requests */
		a_tcp->client.collect++; 
		//fprintf(stderr, "%s established\n", buf);
		/* Alloc the state tracking structure and set it up*/
		conn_state=(conn_state_t *)malloc(sizeof( conn_state_t));
		conn_state->next_packet_offset = 0;
		conn_state->state = wait_full_header;
		*conn_state_ptr = conn_state;
		BEEN_HERE;
		return;
	}
	if ( (a_tcp->nids_state == NIDS_CLOSE) ||
	     (a_tcp->nids_state == NIDS_RESET) ||
	     (a_tcp->nids_state == NIDS_TIMED_OUT) ){
		BEEN_HERE;
		/* free conn. related data */
		free(conn_state);
		*conn_state_ptr=NULL;
		/* connection has been closed normally */
		//fprintf(stderr, "%s closing\n", buf);
		BEEN_HERE;
		return;
	}
	if (a_tcp->nids_state == NIDS_DATA) {
		BEEN_HERE;
		/* new data has arrived in the client site */

		struct e2k_header_t *hdr;
		struct half_stream *client = &a_tcp->client;
		conn_state = *conn_state_ptr;
		int next_packet_offset = 0;
		BEEN_HERE;

		if (conn_state->state == wait_full_header ) {
			BEEN_HERE;
			//printf("wait_full_header\n");
			/* Have we got enought data to be able to read 
			 * a full header? */
			if ( (client->count - client->offset) < 
			   EDONKEY_HEADER_SIZE){
				BEEN_HERE;
				/* not enought data, keep all the
				 * buffer's data
				 */
				nids_discard (a_tcp, 0);
				BEEN_HERE;
			} else {
				/* Debuging printf's*/
				BEEN_HERE;
				/*printf("\tCount_new=%i\n",client->count_new);
				printf("\tDiff=%i, count=%i, offset=%i\n",client->count - client->offset,client->count,client->offset);
				printf("\tnext_packet_offset=%i\n",conn_state->next_packet_offset);*/

				/* Read header data */
				(void*)hdr = (void*)client->data;
				/* Is the current packet a intersting one? */
				if (hdr->msg == EDONKEY_FILE_REQUEST_OPCODE) {
					printf("!!! Header FILE REQUEST !!!\n");
					fprintf(stderr, "%s\n", buf);	// we print the connection parameters
					printf ("Proto=0x%02x Packet_size=%i Msg_id=0x%02x\n", hdr->proto, hdr->packet_size, hdr->msg);
					/* Process the packet. Keep all data. */
					conn_state->state= wait_full_packet;
					nids_discard (a_tcp, 0);
				} else{
					conn_state->state= skip_full_packet;
					/*Calc next packet's offset */
					conn_state->next_packet_offset = 
						client->offset +
						EDONKEY_HEADER_SIZE -1  +
						hdr->packet_size;
				}
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
		} else if (conn_state->state ==  wait_full_packet ) {
			printf("### wait_full_packet ###\n");

			/* Read header data */
			(void*)hdr = (void*)client->data;
			/*Calc next packet's offset */
			next_packet_offset = client->offset + 
				EDONKEY_HEADER_SIZE -1  + hdr->packet_size;
		
			/* Have we got enought data? */
			if (client->count > conn_state->next_packet_offset){
				/* yes, we have */
				if ( hdr->msg == EDONKEY_FILE_REQUEST_OPCODE){

					/* Reach the hash inside the message
					 * (inside the packet). Ptr Arithm.*/
					char* hash = (client->data + EDONKEY_HEADER_SIZE); 
					int i = 0;
					printf("File Request: ");
					for (i = 0; i < 16; i++){
						printf("%02X ",hash[i]);
					}
					printf("\n");
				

					/* Debuging printf's*/
					BEEN_HERE;
					fprintf(stderr, "%s\n", buf);	// we print the connection parameters
					printf("\tCount_new=%i\n",client->count_new);
					printf("\tDiff=%i, count=%i, offset=%i\n",client->count - client->offset,client->count,client->offset);
					printf("\tnext_packet_offset=%i\n",conn_state->next_packet_offset);
				}
				/* Since we are done with this packet,
				 * let's "skip" it :-) */
				conn_state->state= skip_full_packet;
				conn_state->next_packet_offset = next_packet_offset;
			} else {
				/*Not enought data? Keep the the one he already
				 * have and go get some more */
				nids_discard (a_tcp, 0);
				conn_state->state = wait_full_packet;
			}
		} else if (conn_state->state ==  skip_full_packet ) {
			BEEN_HERE;
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

		// So, we have some normal data to take care of.
		if (a_tcp->client.count_new) {
		}
		BEEN_HERE;
		/* fprintf(stderr, "%s\n", buf);	// we print the connection parameters */
		BEEN_HERE;
		// (saddr, daddr, sport, dport) accompanied
		// by data flow direction (-> or <-)
		return;
	}
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
