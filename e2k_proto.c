/**@file e2k_proto.c
 * @brief edonkey protocol handling funtions
 * @author Tiago Alves Macambira
 * @version $Id: e2k_proto.c,v 1.13 2004-08-31 23:38:03 tmacam Exp $
 * 
 * 
 * Based on sample code provided with libnids and copyright (c) 1999
 * Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
 * See the file COPYING from libnids for license details.
 *
 * (c) Tiago Alves Macambira
 * See COPYING for licence for further license details
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#include "e2k_defs.h"
#include "e2k_utils.h"

#include "e2k_proto.h"

/* ********************************************************************  
 *  Private functions
 * ******************************************************************** */

/* NOTICE:
 *	6 = 1 + 5 = pkt.data[1 byte] + (hdr.proto + hdr.size)[5 bytes]
 *
 *	The size field only accounts for payload size, not for packet size
 *
 */
#define COMPRESSED_DATA_HEADER_LEN (sizeof(struct e2k_packet_emule_data_compressed_t) - 6) 
#define SENDING_DATA_HEADER_LEN (sizeof(struct e2k_packet_sending_part_t) - 6)

static inline int hashes_are_equal(const struct e2k_hash_t* h1,
		const struct e2k_hash_t* h2)
{
	return (memcmp(h1,h2,sizeof(struct e2k_hash_t)) == 0);
}

static inline void copy_hash(struct e2k_hash_t* h1, struct e2k_hash_t* h2)
{
	memcpy(h1,h2,sizeof(struct e2k_hash_t));
}




/* ********************************************************************  
 *  Private functions
 *  
 *  Data reassembly, de-compression, oportunistic caching of data and
 *  bla-bla-bla functions
 *  
 * ******************************************************************** */

static inline int e2k_proto_write_to_cache( const conn_state_t* connection,
		const struct e2k_hash_t* hash, dword start_offset,
		dword end_offset, const byte* data)
{
	int res;

	/* Oportunistic caching of downloaded files support */
	if ( (connection->download_writer != NULL) &&
	     hashes_are_equal(&connection->download_hash,hash) )
	{
		res = writers_pool_writer_write(connection->download_writer,
			start_offset,
			end_offset,
			data);
		assert( res == WRITERS_POOL_OK );
	}

	return 0;
}

/* ********************************************************************  
 *  Global variables - to avoid alloc and dealloc of local vars.
 * ******************************************************************** */


/* ********************************************************************  
 *  Global defines - error handling macros 
 * ******************************************************************** */

#define CHECK_IF_NULL(ptr) \
        do { if ( ptr == NULL ) { goto null_error; }}while(0)


/* ********************************************************************  
 * String hash-tables
 *
 * The arrays below are used to provide an O(1) mapping from Special
 * Tags and Message Desciptions  to their respective descriptions
 * ******************************************************************** */

#define LAST_KNOWN_STAG  0x25
static unsigned char* e2k_special_tags_hash[LAST_KNOWN_STAG + 1] = {
	/*0x0*/ "EDONKEY_STAG_UNKNOWN",
	/*0x1*/ "EDONKEY_STAG_NAME",
	/*0x2*/ "EDONKEY_STAG_SIZE",
	/*0x3*/ "EDONKEY_STAG_TYPE",
	/*0x4*/ "EDONKEY_STAG_FORMAT",
	/*0x5*/ "EDONKEY_STAG_COLLECTION",
	/*0x6*/ "EDONKEY_STAG_PART_PATH",
	/*0x7*/ "EDONKEY_STAG_PART_HASH",
	/*0x8*/ "EDONKEY_STAG_COPIED",
	/*0x9*/ "EDONKEY_STAG_GAP_START",
	/*0xa*/ "EDONKEY_STAG_GAP_END",
	/*0xb*/ "EDONKEY_STAG_DESCRIPTION",
	/*0xc*/ "EDONKEY_STAG_PING",
	/*0xd*/ "EDONKEY_STAG_FAIL",
	/*0xe*/ "EDONKEY_STAG_PREFERENCE",
	/*0xf*/ "EDONKEY_STAG_PORT",
	/*0x10*/ "EDONKEY_STAG_IP",
	/*0x11*/ "EDONKEY_STAG_VERSION",
	/*0x12*/ "EDONKEY_STAG_TEMPFILE",
	/*0x13*/ "EDONKEY_STAG_PRIORITY",
	/*0x14*/ "EDONKEY_STAG_STATUS",
	/*0x15*/ "EDONKEY_STAG_AVAILABILITY",
	/*0x16*/ "EDONKEY_STAG_QTIME",
	/*0x17*/ "EDONKEY_STAG_PARTS",
	/*0x18*/ "UNKNOWN_TAG",
	/*0x19*/ "UNKNOWN_TAG",
	/*0x1a*/ "UNKNOWN_TAG",
	/*0x1b*/ "UNKNOWN_TAG",
	/*0x1c*/ "UNKNOWN_TAG",
	/*0x1d*/ "UNKNOWN_TAG",
	/*0x1e*/ "UNKNOWN_TAG",
	/*0x1f*/ "UNKNOWN_TAG",
	/*0x20*/ "EMULE_STAG_COMPRESSION",
	/*0x21*/ "EMULE_STAG_UDP_CLIENT_PORT",
	/*0x22*/ "EMULE_STAG_UDP_VERSION",
	/*0x23*/ "EMULE_STAG_SOURCE_EXCHANGE",
	/*0x24*/ "EMULE_STAG_COMMENTS",
	/*0x25*/ "EMULE_STAG_EXTENDED_REQUEST"};


	
/* ********************************************************************  
 * edonkey protocol handling funtions - printf_e2k_ fanfare
 *
 * All the functions bellow are used to handle especific edonkey messages.
 * In practice, now, all they do is print to stdout all the relevant
 * parts of each message we are interessted in.
 *
 * We are trying to avoid coping anything and using the structures in-place.
 * to cause in the least possible overhead
 *
 * Wel... all the above was true until we added opportunistic caching of
 * downloaded files  support...
 *
 * ******************************************************************** */

void e2k_proto_handle_metalist(struct e2k_metalist_t* metalist)
{
	dword i = 0;
	int offset = 0;
	struct e2k_metalist_tag_t* tag = NULL;
	/* aux. vars - just to make code easyer to read */
	byte tag_name;
	struct e2k_hash_t* hash = NULL;
	struct e2k_string_t* netstring = NULL;
	dword* read_dword = NULL;
	float* read_float = NULL;

	byte* data = &metalist->data;
	
	fprintf(stdout,"ML{ ");
	for (i = 0; i < metalist->length; i++){
		/*Print the name of the tag */
		tag = (void*)&data[offset];
		if (tag->name.length > 1 ){
			/*Ops! Got a netstring as tag name*/
			fprintf_e2k_string(stdout,&tag->name);
		} else {
			/* We don't know all the possible stag names */
			tag_name = tag->name.str_data;
			if ( tag_name> LAST_KNOWN_STAG) {
				tag_name = EDONKEY_STAG_UNKNOWN;
			} 
			fprintf( stdout, "%s",e2k_special_tags_hash[tag_name]);
		};
		fprintf(stdout,"[");
		offset += (3 + tag->name.length); /* byte word strlen*/

		/* Print the content */
		switch(tag->type){
			case EDONKEY_MTAG_HASH:
				hash = (struct e2k_hash_t*)&data[offset];
				fprintf_e2k_hash(stdout, hash);
				offset += sizeof(struct e2k_hash_t);
				break;
			case EDONKEY_MTAG_STRING:
				netstring = (struct e2k_string_t*)&data[offset];
				fprintf_e2k_string(stdout,netstring);
				offset += (2 + netstring->length);
				break;
			case EDONKEY_MTAG_DWORD:
				read_dword = (dword*)&data[offset];
				fprintf(stdout,"%u",*read_dword);
				offset += sizeof(dword);
				break;
			case EDONKEY_MTAG_FLOAT:
				read_float = (float*)&data[offset];
				fprintf(stdout,"%f",*read_float);
				offset += sizeof(float);
				break;
			case EDONKEY_MTAG_BOOL:
			case EDONKEY_MTAG_BOOL_ARRAY:
			case EDONKEY_MTAG_BLOB:
			case EDONKEY_MTAG_UNKNOWN:
			default:
				/* Ih! Fudeu.... e agora?! */
				/* Don't now what to do! Just return and
				 * ignore the rest of the meta-tag list */
				fprintf(stdout,"???]}");
				return;
		}
		fprintf(stdout,"] ");
	}
	fprintf(stdout,"}");
}

inline void e2k_proto_handle_file_status_answer( struct e2k_packet_file_request_answer_t* packet)
{
	fprintf(stdout,"FILE REQUEST ANSWER hash[");
	fprintf_e2k_hash(stdout, &packet->hash);
	fprintf(stdout,"] filename[");
	fprintf_e2k_string(stdout,&packet->filename);
	fprintf(stdout,"]");
}

inline void e2k_proto_handle_generic_hash(struct e2k_packet_generic_hash_t* packet, unsigned char* msg_name)
{
	fprintf(stdout,"%s hash[", msg_name);
	fprintf_e2k_hash(stdout, &packet->hash);
	fprintf(stdout,"]");
}

inline void e2k_proto_handle_sending_part(struct e2k_packet_sending_part_t* packet, conn_state_t* connection)
{
	int res;

	fprintf(stdout,"SENDING PART hash[");
	fprintf_e2k_hash(stdout, &packet->hash);
	fprintf(stdout,"] offset[%lu,%lu]",
		packet->start_offset, packet->end_offset);

	/* "Never trust the network"
	 *
	 *  - don't try to get more data then what is really there
	 */
	if ( packet->end_offset - packet->start_offset !=
		packet->header.packet_size - SENDING_DATA_HEADER_LEN )
	{
		fprintf( stderr, 
			"ERROR: %s (%s:%i) - data offsets overflow packet size",
			__FUNCTION__, __FILE__, __LINE__);
		fprintf(stdout," BOGUS / CORRUPTED");
		return;
	}

	/* Oportunistic caching of downloaded files support */
/*        if ( (connection->download_writer != NULL) &&*/
/*             hashes_are_equal(&connection->download_hash,&packet->hash) )*/
/*        {*/
/*                res = writers_pool_writer_write(connection->download_writer,*/
/*                        packet->start_offset,*/
/*                        packet->end_offset,*/
/*                        &packet->data);*/
/*                assert( res == WRITERS_POOL_OK );*/
/*        }*/
	e2k_proto_write_to_cache( connection, &packet->hash,
			packet->start_offset, packet->end_offset,
			&packet->data);
}



inline void e2k_proto_handle_hello(struct e2k_packet_hello_t* packet, unsigned char* msg_name)
{
	fprintf( stdout,
		 "%s client_hash[",
		 msg_name);
	fprintf_e2k_hash(stdout,&packet->client_info.client_hash);
	fprintf(stdout,"] ");
	e2k_proto_handle_metalist(
		(struct e2k_metalist_t*)&packet->client_info.meta_tag_list);
}


inline void e2k_proto_handle_client_hello(struct e2k_packet_hello_client_t* packet, unsigned char* msg_name)
{
	fprintf( stdout,
		 "%s is_client[0x%x] client_hash[",
		 msg_name,
		 packet->clienthash_size);
	fprintf_e2k_hash(stdout,&packet->client_info.client_hash);
	fprintf(stdout,"] ");
	e2k_proto_handle_metalist(
		(struct e2k_metalist_t*)&packet->client_info.meta_tag_list);
}

inline void e2k_proto_handle_generic_client_hello(struct e2k_packet_hello_client_t* packet, unsigned char* msg_name)
{
	/* Are we dealing with Hello to a client or to a server?
	 * If it's a client hello, then clienthash_size must be 16!!!
	 * aMule BaseClient.cpp says so...
	 */
	if (packet->clienthash_size == 0x10 && 
	    packet->header.msg == EDONKEY_MSG_HELLO){
		/* Ok. It really seems like a client_hello, keep going */
		e2k_proto_handle_client_hello(packet, msg_name);
	} else {
		e2k_proto_handle_hello( (struct e2k_packet_hello_t* )packet,
				         msg_name);
	}
}


inline void e2k_proto_handle_generic_emule_hello(struct e2k_packet_emule_hello_t* packet, unsigned char* msg_name)
{
	fprintf(stdout,"%s version[%u] ", msg_name, packet->version);
	e2k_proto_handle_metalist(&packet->meta_tag_list);
}
			
inline void e2k_proto_handle_emule_data_compressed(struct e2k_packet_emule_data_compressed_t* packet, conn_state_t* connection)
{
	int res;
	int data_len = 0;
	dword len_unzipped, start_pos;
	e2k_zip_state_t* zip_state;

	fprintf(stdout,"EMULE COMPRESSED DATA hash[");
	fprintf_e2k_hash(stdout, &packet->hash);
	fprintf(stdout,"] offset[%lu,%lu]",
		packet->start_offset,packet->packed_len);

	/* Compressed-data-related setup */
	zip_state = &connection->zip_state;
	assert(&connection->zip_state == &(connection->zip_state));
	data_len = packet->header.packet_size - COMPRESSED_DATA_HEADER_LEN;

	
	/* Is this the begining of a new chunk of COMPRESSED DATA pkts ? */
	if ( zip_state->in_use && (zip_state->start != packet->start_offset) ) {
		res = e2k_zip_destroy(zip_state);
		assert( res == E2K_ZIP_OK );	
	}
	/* Again, is this the start of a new chunk? */
	if ( !zip_state->in_use) {
		/* New chunk of COMPRESSED DATA ahead
		 * Start decompression engine
		 */
		res = e2k_zip_init(zip_state);
		/* Sanity check for future usage */
		zip_state->start = packet->start_offset;
		assert( res == E2K_ZIP_OK );
	}


	res = e2k_zip_unzip(zip_state, &len_unzipped, data_len, 
			&packet->data, 0 );
	start_pos = zip_state->start + zip_state->total_unzipped - len_unzipped;
	if ( res == E2K_ZIP_ERR ){
		fprintf (stdout, " BOGUS *** FAILED *** (%i) : %s ",
				res, zip_state->zs.msg);
		zip_state->ignore = 1;
		/* e2k_zip_destroy(zip_state); */
		return;
	} /*FIXME else if (res == E2K_ZIP_FINISHED) {
	   *	e2k_zip_destroy(zip_state);
	   * }
	   */

	fprintf(stdout, " offset_unzipped[%lu:%lu]",
			start_pos, start_pos + len_unzipped );

	/* Oportunistic caching of downloaded files support */
/*        if ( (connection->download_writer != NULL) &&*/
/*             hashes_are_equal(&connection->download_hash,&packet->hash) )*/
/*        {*/
/*                res = writers_pool_writer_write(connection->download_writer,*/
/*                        start_pos,*/
/*                        start_pos + len_unzipped, |+end is not inclusive+|*/
/*                        zip_state->unzipped_buf);*/
/*                assert( res == WRITERS_POOL_OK );*/
/*        }*/
	e2k_proto_write_to_cache(connection, &packet->hash, start_pos,
			start_pos + len_unzipped, /*end is not inclusive*/
			zip_state->unzipped_buf);
	
}

inline void e2k_proto_request_parts( struct e2k_packet_request_parts_t *packet,
		conn_state_t* connection)
{
	int res;

	fprintf(stdout,"REQUEST PARTS hash[");
	fprintf_e2k_hash(stdout,&packet->hash);
	fprintf(stdout,"] offset_1[%u,%u] offset_2[%u,%u] offset_3[%u,%u]",
		packet->start_offset_1,
		packet->end_offset_1,
		packet->start_offset_2,
		packet->end_offset_2,
		packet->start_offset_3,
		packet->end_offset_3
		);
	
	/* Oportunistic caching of downloaded files support */
	if ( ! hashes_are_equal(&connection->download_hash,&packet->hash)){
		/* FragmentedWriter setup */
		if( connection->download_writer != NULL){
			res = writers_pool_writer_release(w_pool,
                                hash2str(&connection->download_hash));
			assert( res == WRITERS_POOL_OK );
		}
		copy_hash(&connection->download_hash, &packet->hash);
		connection->download_writer = writers_pool_writer_get( w_pool,
				hash2str(&connection->download_hash));
		assert( connection->download_writer != NULL );
	}
	/* Compressed-data-related setup */
	/*res = e2k_zip_destroy(&connection->zip_state);
	connection->zip_state.start = packet->start_offset_1;
	assert( res == E2K_ZIP_OK );*/
}

inline void e2k_proto_handle_file_status(struct e2k_packet_file_status_t *packet)
{
	fprintf( stdout,"FILE STATUS hash[");
	fprintf_e2k_hash(stdout,&packet->hash);
	fprintf( stdout,"] len[%u] bitmap=0x[", packet->len);
	fprintf_e2k_hex(stdout, &packet->bitmap,(packet->len+7)/8);
	fprintf(stdout,"]");
}

inline void e2k_proto_handle_queue_rank(struct e2k_packet_queue_rank_t *packet)
{
	fprintf( stdout, "QUEUE RANK rank[%u]", packet->rank);
}

inline void e2k_proto_handle_emule_queue_ranking (struct e2k_packet_emule_queue_ranking_t *packet)
{
	fprintf( stdout, "QUEUE RANKING rank[%u]", packet->rank);
}

/* ********************************************************************  
 * edonkey protocol handling funtions - implementation
 * ******************************************************************** */

void handle_edonkey_packet(int is_server, char *pkt_data, char *address_str,
		conn_state_t* connection)
{
	struct e2k_header_t *hdr= NULL;
	char *direction = NULL;
	
	hdr = (void*)pkt_data;
	
	/* Print basic log line */
	direction = is_server ? "[S]" : "[C]";
	fprintf( stdout,
		 "[%s][%07u] %s%s proto=0x%02x msg_id=0x%02x size=%u ",
		 strtimestamp(), connection->connection_id,
		 address_str, direction, hdr->proto, hdr->msg,hdr->packet_size);

	/* Print extra information for some message types */
	/*    for classic edonkey protocol messages */
	if (hdr->proto == EDONKEY_PROTO_EDONKEY) {
		if (hdr->msg == EDONKEY_MSG_HELLO ) {
			e2k_proto_handle_generic_client_hello( (void*)pkt_data,
							"CLIENT HELLO");
		} else if (hdr->msg == EDONKEY_MSG_HELLO_ANSWER ) {
			e2k_proto_handle_generic_client_hello( (void*)pkt_data,
							"CLIENT HELLO ANSWER");
		} else if (hdr->msg == EDONKEY_MSG_FILE_REQUEST ) {
			e2k_proto_handle_generic_hash( (void*)pkt_data,
							"FILE REQUEST");
		} else if (hdr->msg == EDONKEY_MSG_NO_SUCH_FILE ) {
			e2k_proto_handle_generic_hash( (void*)pkt_data,
							"NO SUCH FILE");
		} else if (hdr->msg == EDONKEY_MSG_FILE_REQUEST_ANSWER ) {
			e2k_proto_handle_file_status_answer((void*)pkt_data);
		} else if (hdr->msg == EDONKEY_MSG_REQUEST_PARTS ) {
			e2k_proto_request_parts((void*)pkt_data, connection);
		} else if (hdr->msg == EDONKEY_MSG_SENDING_PART ) {
			e2k_proto_handle_sending_part( (void*)pkt_data,
					connection);
		} else if (hdr->msg == EDONKEY_MSG_FILE_STATUS ) {
			e2k_proto_handle_file_status( (void*)pkt_data);
		} else if (hdr->msg == EDONKEY_MSG_QUEUE_RANK ) {
			e2k_proto_handle_queue_rank( (void*)pkt_data);
		}
	/*    for emule extension messages */
	} else if (hdr->proto == EDONKEY_PROTO_EMULE) {
		if (hdr->msg == EMULE_MSG_HELLO) {
			e2k_proto_handle_generic_emule_hello( (void*)pkt_data,
							       "HELLO");
		} else if (hdr->msg == EMULE_MSG_HELLO_ANSWER) {
			e2k_proto_handle_generic_emule_hello( (void*)pkt_data,
							       "HELLO ANSWER");
		} else if (hdr->msg == EMULE_MSG_DATA_COMPRESSED) {
			e2k_proto_handle_emule_data_compressed((void*)pkt_data,
					connection);
		} else if (hdr->msg == EMULE_MSG_QUEUE_RANKING ) {
			e2k_proto_handle_emule_queue_ranking ((void*)pkt_data);
		}

	}

	/* Finish the log line */
	fprintf( stdout, "\n");
	
}
