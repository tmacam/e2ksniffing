/**@file e2k_proto.c
 * @brief edonkey protocol handling funtions
 * @author Tiago Alves Macambira
 * @version $Id: e2k_proto.c,v 1.1 2004-03-11 20:13:49 tmacam Exp $
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
 * edonkey protocol handling funtions
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
