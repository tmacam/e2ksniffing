/* 
 * @author Tiago Alves Macambira
 * @version $Id: main.c,v 1.15 2004-03-03 08:08:51 tmacam Exp $
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
#include <unistd.h>
#include "nids.h"

/*para strerror*/
#include <errno.h>
/*para drop_privilages*/
#include <pwd.h>
#include <grp.h>


#include "main.h"
#include "e2k_defs.h"


#define UNPRIV_USER "nobody"

#define CHECK_IF_NULL(ptr) \
        do { if ( ptr == NULL ) { goto null_error; }}while(0)

/* ********************************************************************  
 *  Global variables
 * ******************************************************************** */

unsigned char e2ksniff_errbuf[256];


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
	strncpy(buf, inet_ntoa(*((struct in_addr *)&(addr.saddr))), 255);
	snprintf(buf + strlen(buf), 255, ":%i,", addr.source);
	strncpy(buf + strlen(buf), inet_ntoa(*((struct in_addr *)&(addr.daddr))),256);
	snprintf(buf + strlen(buf), 255, ":%i", addr.dest);
	return buf;
}

unsigned char* hexstr (unsigned char *data, unsigned int len)
{
        unsigned char* result = NULL;
        int i = 0;

        /* hex of one  byte takes 2 chars. +1 for the ending '/0' */
        result = (char*)calloc( (2*len + 1), sizeof(char));
        if (result == NULL){
                return result;
        }
	
        for(i = 0; i < len; i++) {
                sprintf(&result[2*i], "%02x", data[i]);
        }

        return result;
}

/**@brief Converts MD4 hash into a string
 *
 * This function will "convert" a MD4 hash into its hex-coded string.
 * This string will be dynamic allocated - remember to free it later.
 * 
 * @param e2k_hash the MD4 hash
 */
unsigned char* asprintf_hash(struct e2k_hash_t* hash )
{
	byte* hash_data = hash->data; /* Saving 16 ptrs. indirections*/
	unsigned char* result = NULL;
	int ret = 0;

	ret = asprintf(&result,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		hash_data[0], hash_data[1], hash_data[2], hash_data[3], 
		hash_data[4], hash_data[5], hash_data[6], hash_data[7],
		hash_data[8], hash_data[9], hash_data[10],hash_data[11],
		hash_data[12],hash_data[13],hash_data[14],hash_data[15]);
	if (ret < 0){
		return NULL;
	} else {
		return result;
	}

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
void handle_edonkey_packet(int is_server, char *pkt_data, char *address_str)
{
	struct e2k_header_t *hdr= NULL;
	char *direction = NULL;
	char *hash_str = NULL;
	
	(void*)hdr = (void*)pkt_data;
	
	/* Print basic log line */
	direction = is_server ? "[S]" : "[C]";
	fprintf( stdout,
		 "%s%s proto=0x%02x msg_id=0x%02x size=%i ",
		 address_str, direction, hdr->proto, hdr->msg,hdr->packet_size);

	/* Print extra information for some message types */
	/*    for classic edonkey protocol messages */
	if (hdr->proto == EDONKEY_PROTO_EDONKEY) {
		if (hdr->msg == EDONKEY_MSG_FILE_REQUEST ) {
			struct e2k_packet_file_request_t *file_req = NULL;
			(void *)file_req = (void *)pkt_data;
			hash_str=asprintf_hash(&file_req->hash);
			CHECK_IF_NULL(hash_str);
			fprintf(stdout,"FILE REQUEST hash[%s]",hash_str);
		} else if (hdr->msg == EDONKEY_MSG_REQUEST_PARTS ) {
			struct e2k_packet_request_parts_t *parts_req = NULL;
			(void *)parts_req = (void *)pkt_data;
			hash_str=asprintf_hash(&parts_req->hash);
			CHECK_IF_NULL(hash_str);
			fprintf(stdout,
				"REQUEST PARTS hash[%s] offset_1[%i,%i] offset_2[%i,%i] offset_3[%i,%i]",
				hash_str,
				parts_req->start_offset_1,
				parts_req->end_offset_1,
				parts_req->start_offset_2,
				parts_req->end_offset_2,
				parts_req->start_offset_3,
				parts_req->end_offset_3
				);
		} else if (hdr->msg == EDONKEY_MSG_SENDING_PART ) {
			struct e2k_packet_sending_part_t *sending_pkt = NULL;
			(void *)sending_pkt = (void *)pkt_data;
			hash_str=asprintf_hash(&sending_pkt->hash);
			CHECK_IF_NULL(hash_str);
			fprintf(stdout,"SENDING PART hash[%s] offset[%i,%i]",
					hash_str, 
					sending_pkt->start_offset,
					sending_pkt->end_offset);
		} else if (hdr->msg == EDONKEY_MSG_FILE_STATUS ) {
			struct e2k_packet_file_status_t *status_pkt = NULL;
			char* bitmap_hex_str = NULL;
			(void *)status_pkt = (void *)pkt_data;
			hash_str=asprintf_hash(&status_pkt->hash);
			bitmap_hex_str = hexstr( &status_pkt->bitmap,
						(status_pkt->len+7)/8);
			CHECK_IF_NULL(hash_str);
			fprintf( stdout,
				"FILE STATUS hash[%s] len=%i bitmap=0x[%s]",
				hash_str, 
				status_pkt->len,
				bitmap_hex_str);
			free(bitmap_hex_str);
		} else if (hdr->msg == EDONKEY_MSG_QUEUE_RANK ) {
			struct e2k_packet_queue_rank_t *rank_pkt = NULL;
			(void *)rank_pkt = (void *)pkt_data;
			fprintf( stdout,
				 "QUEUE RANK rank[%i]",
				 rank_pkt->rank);
		}
	/*    for emule extension messages */
	} else if (hdr->proto == EDONKEY_PROTO_EMULE) {
		if (hdr->msg == EMULE_MSG_DATA_COMPRESSED) {
			struct e2k_packet_emule_data_compressed_t *emuledc_pkt = NULL;
			(void *)emuledc_pkt = (void *)pkt_data;
			hash_str=asprintf_hash(&emuledc_pkt->hash);
			CHECK_IF_NULL(hash_str);
			fprintf( stdout,
				"EMULE COMPRESSED DATA hash[%s] offset_start=%i len=%i",
				hash_str, 
				emuledc_pkt->start_offset,
				emuledc_pkt->packed_len);
		} else if (hdr->msg == EMULE_MSG_QUEUE_RANKING ) {
			struct e2k_packet_emule_queue_ranking_t *rank_pkt =NULL;
			(void *)rank_pkt = (void *)pkt_data;
			fprintf( stdout,
				"QUEUE RANKING rank[%i]",
				rank_pkt->rank);
		}

	}

null_error:
	/* Free allocated resources */
	if (hash_str != NULL){
		free(hash_str);
	}

	/* Finish the log line */
	fprintf( stdout, "\n");
	
}


/* ********************************************************************  
 * edonkey state-machine control function
 * ******************************************************************** */

#define HANDLE_STATE_NEED_MORE_DATA -1
#define HANDLE_STATE_SUCCESSFUL 0
#define IS_CLIENT 0
#define IS_SERVER 1

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
 * This function leave conn_state->next_packet_offset intact.
 *
 * @warning next_packet_offset here means "the offset of the NEXT NOT FULLY
 * PROCESSED packet" in the stream.
 *
 * @return HANDLE_STATE_SUCCESSFUL if the it successfuly 
 * completed it's intented function with the available data. It
 * will return HANDLE_STATE_NEED_MORE_DATA otherwise
 *
 * @see EDONKEY_HEADER_SIZE, handle_state_wait_full_packet
 */
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
#ifdef BE_VERBOSE
		/* Read header data */
		(void*)hdr = (void*)(halfstream->data + offset_shift);
		/* Don't we perl lovers/haters adore verbose outputs? */
		/*fprintf(stdout,"Header > %s proto=0x%02x packet_size=%i msg_id=0x%02x\n", state->connection->address_str, hdr->proto, hdr->packet_size, hdr->msg);*/
#endif
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

/**@brief  State Machine control - Waiting for a Full packet
 * 
 * So we have at least a complete donkey packet header available. With
 * it we can calculate the size of the donkey packet we are currently reading
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
 * waiting for the full packet.
 *
 * @warning this state SHOULD only be reached through wait_full_header
 * @warning next_packet_offset here means "the offset of the NEXT NOT FULLY
 * PROCESSED packet" in the stream.
 *
 * @return HANDLE_STATE_SUCCESSFUL if the it successfuly completed it's
 * intented function with the available data. Otherwise, it will return
 * HANDLE_STATE_NEED_MORE_DATA.
 */
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
		state->next_packet_offset = following_packet_offset;
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
 * 2 states used ). State information is stored in half_conn_state and is
 * controled by the handle_state_* functions.
 *
 * @param is_server boolean, indicating if the halfstream  were given is from
 * the server-side of the  connection.
 *
 * @param halfstrem the half_stream of the connection we will process
 *
 * @param state state-machine information for this side of the connection
 *
 * @return the amount of data that MUST be left in the halfstream to be further
 * processed latter, i.e., what we receive more data.
 *
 * @see conn_state_t, half_conn_state_t
 */
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


/* ********************************************************************  
 * Sniffing control functions
 * ******************************************************************** */

inline void handle_tcp_close(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	conn_state_t* conn_state = *conn_state_ptr;
	
	/* Ignore both client and server-side streams */
	a_tcp->client.collect = 0;
	a_tcp->server.collect = 0; 
	
	fprintf(stdout, "%s closed\n", conn_state->address_str);
	/* free conn. related data */
	free(conn_state);
	*conn_state_ptr=NULL;
	/* connection was closed normally */
}

inline void handle_tcp_data(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	conn_state_t* conn_state = *conn_state_ptr;
	unsigned int discard_amount = 0;
	int debug = 0; /*FIXME*/

	/*Should we process this TCP connection? */
	if (conn_state->ignore){
		fprintf( stdout, "%s ignoring\n", conn_state->address_str);
		handle_tcp_close(a_tcp,conn_state_ptr);
	}

	/* So, where is this new data comming from? */
	if (a_tcp->client.count_new > 0){
		discard_amount = handle_halfstream_data( IS_CLIENT,
							&a_tcp->client,
							&conn_state->client);
		++debug;
	}
	if (a_tcp->server.count_new > 0){
		discard_amount = handle_halfstream_data( IS_SERVER,
							&a_tcp->server,
							&conn_state->server);
		++debug;
	}

	if(debug > 2){
		fprintf(stderr,"\n\n\n == SERVER AND CLIENT DATA ARRIVED SIMUTANEOUSLY!!!!\n\n\n");
		exit(1);
	}
	nids_discard(a_tcp, discard_amount);
}

inline void handle_tcp_establish(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	conn_state_t* conn_state = NULL;

	/* Follow both client and server-side streams 
	 * but don't follow any urgent data strem*/
	a_tcp->client.collect++; 
	a_tcp->server.collect++; 
	
	/* Alloc the state tracking structure */
	conn_state=(conn_state_t *)malloc(sizeof( conn_state_t));
	/* FIXME : check if null*/
	/* Register/link state tracking data with the stream*/
	*conn_state_ptr = conn_state;
	
	/* Setup state tracking structures */
	conn_state->ignore = 0;
	/* - address_str */
	strncpy(conn_state->address_str, address_str(a_tcp->addr),
			CONN_STATE_ADDRESS_STR_SZ -1);
	conn_state->address_str[CONN_STATE_ADDRESS_STR_SZ -1] = '\0';
	/* - client-side state-machine */
	conn_state->client.next_packet_offset = 0;
	conn_state->client.state = wait_full_header;
	conn_state->client.connection = conn_state;
	conn_state->client.blessed = 0;
	/* - server-side state-machine*/
	conn_state->server.next_packet_offset = 0;
	conn_state->server.state = wait_full_header;
	conn_state->server.connection = conn_state;
	conn_state->server.blessed = 0;

	fprintf(stdout, "%s established\n", conn_state->address_str);
}



void tcp_callback(struct tcp_stream *a_tcp, conn_state_t **conn_state_ptr)
{
	
	if (a_tcp->nids_state == NIDS_DATA) {
		/* new data has arrived in the stream */
		handle_tcp_data(a_tcp, conn_state_ptr);
	} else	if (a_tcp->nids_state == NIDS_JUST_EST) {
		/* A new connection was established.
		 * Is it a edonkey connection? Should we sniff it?
		 */
		if (a_tcp->addr.dest == EDONKEY_CLIENT_PORT) {
			handle_tcp_establish(a_tcp,conn_state_ptr);
		}
	} else if ( (a_tcp->nids_state == NIDS_CLOSE) ||
	     (a_tcp->nids_state == NIDS_RESET) ||
	     (a_tcp->nids_state == NIDS_TIMED_OUT) ){
		handle_tcp_close(a_tcp,conn_state_ptr);
	};
	return;
}


/* ********************************************************************  
 * Security and resource control functions
 * ******************************************************************** */
/**@brief Callback used by libNIDS to notify that it has run out of memory
 */
void out_of_memory_callback()
{
	fprintf(stdout,"NDIS run out of memory!!!\n");
	/*fsync(stdout);*/ 
	fprintf(stderr,"NDIS run out of memory!!!\n");
	/*fsync(stderr);*/
	/* FIXME so... now what?! Exit, call a "save yourselves function?" */
	exit(1);
}

/**@brief Drop root privilages 
 *
 * This function will drop any superuser privilage of the current process by
 * setuid-ing into unpriv_user.
 *
 * If, by some unknown reason, unpriv_user is
 * also a superuser, the function will return with error.
 *
 * @param unpriv_user the name of the unprivileged user the process will
 * impersonate.
 *
 * @return 0 in case of success. A non-zero value in case of error.
 */
int drop_privilages(const unsigned char* unpriv_user)
{
	struct passwd *pw = NULL;

	/*FIXME clen the env? */
	
	/* Is there any privileges to be dropped? Am I a superuser? */
	if (getuid() == 0) {
		/* Get unpriv_user's UID and GID */
		if ( (pw = getpwnam (unpriv_user)) == NULL ){
			snprintf( e2ksniff_errbuf,
				  sizeof(e2ksniff_errbuf) -1,
				  "There is no user '%s'",
				  unpriv_user);
			goto error;
		} 
		/* Change GID */
		if ( setgid(pw->pw_gid) != 0 ){
			snprintf( e2ksniff_errbuf,
				 sizeof(e2ksniff_errbuf) -1,
				 "Cannot change GID: %s",
				 strerror(errno) );
			goto error;
		}
		/* Clean the supplementary group ID list*/
		if ( setgroups(0,NULL) != 0 ) {
			snprintf( e2ksniff_errbuf,
				  sizeof(e2ksniff_errbuf) -1,
				  "Could not clen the supplementary group IDs list");
			goto error;
			
		}
		/* Finally, change the UID*/
		if ( setuid(pw->pw_uid) != 0 ){
			snprintf( e2ksniff_errbuf,
				 sizeof(e2ksniff_errbuf) -1,
				 "Cannot change UID: %s",
				 strerror(errno) );
			goto error;
		}		
		/* Am I still a superuser ? 
		 * unpriv_user must be a superuser then. */
		if ( (getuid() == 0) || (getgid() == 0) ) {
			snprintf( e2ksniff_errbuf,
				  sizeof(e2ksniff_errbuf) -1,
				  "%s is a superuser - can't drop privileges by impersonating a superuser: is nonsense, dude!", unpriv_user);
			goto error;
		}
	} 
	
	/* Success */
	return 0;
error:
	return 1;
}

/* ********************************************************************  
 * Main program
 * ******************************************************************** */

int main(int argc, char* argv[])
{
	/* Setup libNIDS - defaults */
	nids_params.device = "any";
	nids_params.one_loop_less = 0; /* We depend of this semantic */
	nids_params.scan_num_hosts = 0; /* Turn port-scan detection off */
	nids_params.no_mem = out_of_memory_callback;
	/* nids_params.n_hosts=1024; * FIXME value too small? */

	/* Load recorded trace-file or sniff the network?*/
	if (argc > 1){
		nids_params.device = NULL;
		nids_params.filename = argv[1];
		printf(" == Loading trace file: %s\n",nids_params.filename );
	} else {
		printf(" == No tracefile given. Sniffing from the network.\n");
	}

	/* Start libNIDS engine */
	if (!nids_init()) {
		fprintf(stderr, " == ERROR: libNIDS error: %s\n", nids_errbuf);
		exit(1);
	}

	/*  DROP PRIVILEGES !!!!  */
	if( (nids_params.device != NULL) && 
	    (drop_privilages(UNPRIV_USER) != 0) ){
		fprintf( stderr, " == ERROR: Could not drop privileges: %s\n",
			e2ksniff_errbuf);
		exit(1);
	} else {
		fprintf( stdout,
			 " == Droped privilages. Impersonating '%s'\n",
			 UNPRIV_USER);
	}

	nids_register_tcp(tcp_callback);
	
	printf(" == Sniffing started.\n");
	nids_run(); /* Loop forever*/
	return 0;
}
