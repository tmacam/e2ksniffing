/**@file e2k_proto.c
 * @brief edonkey protocol handling funtions
 * @author Tiago Alves Macambira
 * @version $Id: e2k_proto.c,v 1.2 2004-03-15 03:24:03 tmacam Exp $
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

#include "e2k_defs.h"
#include "e2k_utils.h"

#include "e2k_proto.h"

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
	/*0x18*/ NULL,
	/*0x19*/ NULL,
	/*0x1a*/ NULL,
	/*0x1b*/ NULL,
	/*0x1c*/ NULL,
	/*0x1d*/ NULL,
	/*0x1e*/ NULL,
	/*0x1f*/ NULL,
	/*0x20*/ "EMULE_STAG_COMPRESSION",
	/*0x21*/ "EMULE_STAG_UDP_CLIENT_PORT",
	/*0x22*/ "EMULE_STAG_UDP_VERSION",
	/*0x23*/ "EMULE_STAG_SOURCE_EXCHANGE",
	/*0x24*/ "EMULE_STAG_COMMENTS",
	/*0x25*/ "EMULE_STAG_EXTENDED_REQUEST"};


	
/* ********************************************************************  
 * edonkey protocol handling funtions - forward declaration
 * ******************************************************************** */

int e2k_proto_handle_metalist(struct e2k_metalist_t* metalist)
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
		(void*)tag = (void*)&data[offset];
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
				fprintf(stdout,"%i",*read_dword);
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

inline void e2k_proto_handle_sending_part(struct e2k_packet_sending_part_t* packet)
{
	fprintf(stdout,"SENDING PART hash[");
	fprintf_e2k_hash(stdout, &packet->hash);
	fprintf(stdout,"] offset[%i,%i]",
		packet->start_offset, packet->end_offset);
}



inline void e2k_proto_handle_hello(struct e2k_packet_hello_t* packet, unsigned char* msg_name) {
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
		 packet->hello_client_signature);
	fprintf_e2k_hash(stdout,&packet->client_info.client_hash);
	fprintf(stdout,"] ");
	e2k_proto_handle_metalist(
		(struct e2k_metalist_t*)&packet->client_info.meta_tag_list);
}

inline void e2k_proto_handle_generic_client_hello(struct e2k_packet_hello_client_t* packet, unsigned char* msg_name)
{
	if (packet->hello_client_signature == 0x10 &&
	    packet->header.msg == EDONKEY_MSG_HELLO){
		/* Ok. It really seems like a client_hello, keep going */
		e2k_proto_handle_client_hello(packet, msg_name);
	} else {
		e2k_proto_handle_hello( (struct e2k_packet_hello_t* )packet,
				         msg_name);
	}
}


inline void e2k_proto_handle_generic_emule_hello(struct e2k_packet_emule_hello_t* packet, unsigned char* msg_name) {
	fprintf(stdout,"%s version[%i] ", msg_name, packet->version);
	e2k_proto_handle_metalist(&packet->meta_tag_list);
}
			
inline void e2k_proto_handle_emule_data_compressed(struct e2k_packet_emule_data_compressed_t* packet)
{
	fprintf(stdout,"EMULE COMPRESSED DATA hash[");
	fprintf_e2k_hash(stdout, &packet->hash);
	fprintf(stdout,"] offset[%i,%i]",
		packet->start_offset,packet->packed_len);
}

/* ********************************************************************  
 * edonkey protocol handling funtions - implementation
 * ******************************************************************** */

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
			e2k_proto_handle_sending_part( (void*)pkt_data);
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
		if (hdr->msg == EMULE_MSG_HELLO) {
			e2k_proto_handle_generic_emule_hello( (void*)pkt_data,
							       "HELLO");
		} else if (hdr->msg == EMULE_MSG_HELLO_ANSWER) {
			e2k_proto_handle_generic_emule_hello( (void*)pkt_data,
							       "HELLO ANSWER");
		} else if (hdr->msg == EMULE_MSG_DATA_COMPRESSED) {
			e2k_proto_handle_emule_data_compressed((void*)pkt_data);
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
