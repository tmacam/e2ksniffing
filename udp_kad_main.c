/**@file udp_main.c
 * @brief main - Program, libs, and logging facilities setup and handling for
 *        UDP query messages
 * @author Tiago Alves Macambira
 * @version $Id
 * 
 * This code is based on udp_main.c,v 1.3 2004/04/01 22:49:28 
 * 
 * Based on sample code provided with libnids and copyright (c) 1999
 * Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
 * See the file COPYING from libnids for license details.
 *
 *
 * (c) Tiago Alves Macambira
 * See COPYING for licence for further license details
 *
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "nids.h"
#include "pcap.h"
#include <syslog.h>

#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

#include <assert.h>

#include "main.h"
#include "kad_defs.h"
#include "e2k_utils.h"
#include "e2k_zip.h"

/*FIXME gotta exist a better way to do this */
#include "kad_opcode_strs.c"

/* ********************************************************************  
 *  Global defines - error handling macros 
 * ******************************************************************** */

#define CHECK_IF_NULL(ptr) \
        do { if ( ptr == NULL ) { goto null_error; }}while(0)

#define KAD_ZIP_MAXIMUM_LEN 50000

/* ********************************************************************  
 *  Global variables - Private to this module
 * ******************************************************************** */

unsigned char e2ksniff_errbuf[256];

pcap_t* pcap_descriptor = NULL;
unsigned long int n_queries;
time_t next_syslog_report_time = 0;
int is_sniffing = 0;

//inline void syslog_drops(void);
int rotate_logfile( int interval, int max_size );




/* ********************************************************************  
 * Protocol related functions
 * ******************************************************************** */

/**@brief Reads a metalist from a File Info message and  gets the file's size
 * and name from it.
 *
 * This function will return, throught it's arguments filename and filesize,
 * a pointer to the the position inside the metalist where the file's name
 * and size are stored. So, their contents will be valid as long as the
 * metalist given as argument is valid.
 *
 * Upon the function's entry the return-arguments will be NULL'ified
 * 
 * @param metalist the metalist
 * @param filename where a pointer to the filename will be stored
 * @param file_size where a pointer to the file's size will be stored
 */
inline static void get_file_details_from_metalist(
		struct e2k_metalist_t* metalist, 
		struct e2k_string_t** filename,
		dword** file_size)
{
	dword i = 0;
	int offset = 0;
	struct e2k_metalist_tag_t* tag = NULL;
	/* aux. vars - just to make code easyer to read */
	byte tag_name;
	struct e2k_string_t* netstring = NULL;
	
	/* NULLifing our answers - to avoid returning previous responses. */
	*filename = NULL;
	*file_size = NULL;

	byte* data = &metalist->data;
	
	/* Sanity check */
	if (metalist->length > 16 ){
		return;
	}
	
	for (i = 0; i < metalist->length; i++){
		tag = (void*)&data[offset];
		/*Get the name of the tag */
		if (tag->name.length > 1 ){
			/*Ops! Got a netstring as tag name
			 * It doesn't interest us - IF left for legibility */
			tag_name = EDONKEY_STAG_UNKNOWN;
		} else {
			tag_name = tag->name.str_data;
		};
		offset += (3 + tag->name.length); /* byte word strlen*/

		/* Get the content */
		switch(tag->type){
			case EDONKEY_MTAG_HASH:
				offset += sizeof(struct e2k_hash_t);
				break;
			case EDONKEY_MTAG_STRING:
				netstring = (struct e2k_string_t*)&data[offset];
				if(tag_name == EDONKEY_STAG_NAME){
					*filename = netstring;
				}
				offset += (2 + netstring->length);
				break;
			case EDONKEY_MTAG_DWORD:
				if(tag_name == EDONKEY_STAG_SIZE){
					*file_size = (dword*)&data[offset];
				}
				offset += sizeof(dword);
				break;
			case EDONKEY_MTAG_FLOAT:
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
				return;
		}
	}
}

/* ********************************************************************  
 * Utility functions
 * ******************************************************************** */

/*FIXME move it to e2k_zip.c*/
/**@brief Uncompress a packed packet.
 *
 * Header contents are left intact...
 *
 * @param packed_pkt 
 * @param on entry, the length of the packed packet. On successful exit,
 * the len of the unpacket packet.
 *
 * @result a pointer to the decompressed packet, in case of success; NULL
 * otherwise.
 */
struct e2k_udp_header_t* kad_zip_uncompress(struct e2k_udp_header_t* packed_pkt,
		int* len)
{
	static char unzipped_buf[KAD_ZIP_MAXIMUM_LEN];
	uLongf unzipped_len = KAD_ZIP_MAXIMUM_LEN;
	char* zipped_buf = (char*) packed_pkt;
	struct e2k_udp_header_t* result;
	int err;
	
	err = uncompress(&unzipped_buf[2], &unzipped_len, 
				&zipped_buf[2], (*len)-2);
	if (err != Z_OK){
		fprintf(stdout," >>> %i <<< ",err);
		return NULL;
	}
	
	/* Setup missing fields*/
	result = (struct e2k_udp_header_t*) unzipped_buf;
	result->proto = packed_pkt->proto;
	result->msg = packed_pkt->msg;
	*len= unzipped_len + 2;
	return result;
}

/**@brief Endianness crazyness - BigEndian? */
struct e2k_hash_t* kad_key_to_hash(struct e2k_hash_t* kad_key){
	int i;
	static struct e2k_hash_t hash;
	byte* b = (byte*)&hash;

	dword* _key = (dword*)kad_key;

	for (i=0; i<16; i++) {
		b[i] = (byte)(_key[i/4] >> (8*(3-(i%4))));
	}
	
	return &hash;
}

void fprintf_kad_key(FILE* stream,struct e2k_hash_t* key)
{
	fprintf_e2k_hash(stream,kad_key_to_hash(key));
}

void fprintf_kad_udp_peer(FILE* stream, struct kad_udp_peer_t* peer)
{
	fprintf(stream," peer: ");
	fprintf_kad_key( stream, &peer->id);
	fprintf(stream,":%lu:%u:%u:0x%02x", peer->ip, peer->udp_port,
			peer->tcp_port, peer-> type);
}

void fprintf_kad_taglist(FILE* stream, struct kad_udp_taglist_t* taglist)
{
	dword i = 0;
	int offset = 0;
	struct e2k_metalist_tag_t* tag = NULL;

	/* aux. vars - just to make code easyer to read */
	byte tag_name;
	struct e2k_hash_t* hash = NULL;
	struct e2k_string_t* netstring = NULL;
	byte* read_byte = NULL;
	word* read_word = NULL;
	dword* read_dword = NULL;
	float* read_float = NULL;

	byte* data = &taglist->data;
	
	fprintf(stream,"TAGLIST{ len: %lu ", taglist->length);
	for (i = 0; i < taglist->length; i++){
		/*Print the name of the tag */
		tag = (void*)&data[offset];
		if (tag->name.length > 1 ){
			/*Ops! Got a netstring as tag name*/
			fprintf_e2k_string(stream,&tag->name);
		} else {
			/* We don't know all the possible stag names */
			tag_name = tag->name.str_data;
			fprintf( stream, "%s",kad_special_tags_hash[tag_name]);
		};
		fprintf(stream,"[");
		offset += (3 + tag->name.length); /* byte word strlen*/

		/* Print the content */
		switch(tag->type){
			case EDONKEY_MTAG_HASH:
				hash = (struct e2k_hash_t*)&data[offset];
				fprintf_e2k_hash(stream, hash);
				//fprintf(stream," kadkey: ");
				//fprintf_kad_key(stream, hash);
				offset += sizeof(struct e2k_hash_t);
				break;
			case EDONKEY_MTAG_STRING:
				netstring = (struct e2k_string_t*)&data[offset];
				fprintf_e2k_string(stream,netstring);
				offset += (2 + netstring->length);
				break;
			case EDONKEY_MTAG_UINT8:
				read_byte = (byte*)&data[offset];
				fprintf(stream,"%u",*read_byte);
				offset += sizeof(byte);
				break;
			case EDONKEY_MTAG_UINT16:
				read_word = (word*)&data[offset];
				fprintf(stream,"%u",*read_word);
				offset += sizeof(word);
				break;
			case EDONKEY_MTAG_DWORD:
				read_dword = (dword*)&data[offset];
				fprintf(stream,"%u",*read_dword);
				offset += sizeof(dword);
				break;
			case EDONKEY_MTAG_FLOAT:
				read_float = (float*)&data[offset];
				fprintf(stream,"%f",*read_float);
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
				fprintf(stream,"??? 0x%02x ???]}", tag->type);
				return;
		}
		fprintf(stream,"] ");
	}
	fprintf(stream,"}");
}

void fprintf_kad_publish_entry (FILE* stream,
		struct kad_udp_publish_entry_t* entry)
{

	fprintf(stream," [entry ");
	fprintf_kad_key( stream, &entry->id);
	fprintf(stream," ");
	fprintf_kad_taglist(stream, &entry->taglist);
	fprintf(stream," entry] ");

}



/* ********************************************************************  
 * Message decoding functions
 * ******************************************************************** */

void kad_proto_handle_request(struct kad_udp_packet_request_t* packet)
{
	/* Request type is "cleaned" before processing.
	 * Just see eMule code - CKademliaUDPListener::processKademliaRequest
	 */
	packet->type &= 0x1F; 
	
	fprintf(stdout," para: 0x%02x %s target: ",packet->type,
			kad_params_hash[packet->type]);
	fprintf_kad_key(stdout,&packet->target);
	fprintf(stdout," receiver: ");
	fprintf_kad_key(stdout,&packet->receiver);
}

void kad_proto_handle_response(struct kad_udp_packet_response_t* packet)
{
	int i = 0;
	struct kad_udp_peer_t* peers = NULL;

	fprintf(stdout," target: ");
	fprintf_kad_key(stdout,&packet->target);
	fprintf(stdout," count: %02u",packet->count);

	peers = &packet->peers;
	for (i = 0; i < packet->count; i++){
		fprintf_kad_udp_peer(stdout, &peers[i]);
	}
}

void kad_proto_handle_publish_res(struct kad_udp_packet_publish_res_t* packet)
{
	fprintf(stdout," file: ");
	fprintf_kad_key(stdout,&packet->file);
	fprintf(stdout," load: %u",packet->load);
}

void kad_proto_handle_publish_req(struct kad_udp_packet_publish_req_t* packet)
{
	int i = 0;
	
	fprintf(stdout," target: ");
	fprintf_kad_key(stdout,&packet->target);
	fprintf(stdout," count: %u",packet->count);

	if(packet->count > 0){
		fprintf_kad_publish_entry(stdout,&packet->publish_entries);
	}
}

void kad_proto_handle_search_req(struct kad_udp_packet_search_req_t* packet, int len)
{
	
	fprintf(stdout," target: ");
	fprintf_kad_key(stdout,&packet->target);
	fprintf(stdout," restrictive: %u",packet->restrictive);
	
	len -= sizeof(struct e2k_udp_header_t);
	if (len == 17) {
		if (packet->restrictive) {
			fprintf(stdout, " SOURCE");
		} else {
			fprintf(stdout, " KEYWRD");
		}
	} else if ( len > 17 && packet->restrictive ) {
		fprintf (stdout," SEARCH");
	}
}

/* ********************************************************************  
 * Sniffing control functions
 * ******************************************************************** */

void udp_callback(struct tuple4* addr, char* buf, int len, void* not_used)
{
	struct e2k_udp_header_t* packet = NULL;
	struct e2k_string_t* filename = NULL;
	dword* filesize = NULL;

	/* Is this really a kad packet? */
	packet = (void*)buf;
	if ( len < sizeof(struct e2k_udp_header_t) ||
	     len > PACKET_MAXIMUM_SIZE ||
	     ( packet->proto != KAD_PROTO_KAD && 
	       packet->proto != KAD_PROTO_PACKED && 
	       packet->proto != EDONKEY_PROTO_EDONKEY ) )
	{
		/* No, it is not. Ignore it! */
		return;
	}

	/* OK. It *IS* a kad packet.. */
	fprintf(stdout,"addr: %s size: %i ",
			address_str(*addr),len);
	//fprintf(stdout,"udp_port: %u size: %i ", addr->source,len);

	switch(packet->proto){
	case KAD_PROTO_PACKED:
		if (packet = kad_zip_uncompress(packet,&len)) {
			fprintf(stdout,"KAD PAK msg: 0x%02x %s",packet->msg,
				kad_opcodes_hash[packet->msg]);
			/* yeah, don't break - continue in KAD_PROTO_KAD*/
		} else{
			fprintf(stdout,"KAD PAK BOGUS\n"); 
			break;
		}
	case KAD_PROTO_KAD:
		//fprintf(stdout,"KAD STD msg: 0x%02x ",packet->msg);
		if (packet->proto == KAD_PROTO_KAD) {
			fprintf(stdout,"KAD STD msg: 0x%02x %s",packet->msg,
				kad_opcodes_hash[packet->msg]);
		};
		switch(packet->msg){
		case KADEMLIA_REQ:
			kad_proto_handle_request((struct kad_udp_packet_request_t*)packet);
			break;
		case KADEMLIA_RES:
			kad_proto_handle_response((struct kad_udp_packet_response_t*)packet);
			break;
		case KADEMLIA_PUBLISH_RES:
			kad_proto_handle_publish_res((void*)packet);
			break;
		case KADEMLIA_PUBLISH_REQ:
			kad_proto_handle_publish_req((void*)packet);
			break;
		case KADEMLIA_SEARCH_REQ:
			kad_proto_handle_search_req((void*)packet,len);
			break;
		case KADEMLIA_SEARCH_RES:
			kad_proto_handle_publish_req((void*)packet);
			break;
		}
		fprintf(stdout,"\n");
		break;
	case EDONKEY_PROTO_EDONKEY:
		fprintf(stdout,"E2K EML msg: 0x%02x\n",packet->msg);
		break;
	default:
		return;
	}

}


/* ********************************************************************  
 * Security and resource control functions
 * ******************************************************************** */
/**@brief Callback used by libNIDS to notify that it has run out of memory
 */
void out_of_memory_callback()
{
	fprintf(stdout," ==UDP== ERROR: NDIS run out of memory!!!\n");
	fflush(stdout); 
	fprintf(stderr," ==UDP== ERROR: NDIS run out of memory!!!\n");
	fflush(stderr);
	syslog( nids_params.syslog_level,
		" == ERROR: NIDS run out of memory!!!"); 
	/* FIXME so... now what?! Exit, call a "save yourselves function?" */
	abort();
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
 * @return 0 in case of success. -1 in case of error.
 */
int drop_privilages(const unsigned char* unpriv_user)
{
	struct passwd *pw = NULL;

	/*FIXME clean the env? */
	
	/* Is there any privileges to be dropped? Am I a superuser? */
	if (getuid() == 0) {
		/* Get unpriv_user's UID and GID */
		if ( (pw = getpwnam (unpriv_user)) == NULL ){
			snprintf( e2ksniff_errbuf,
				  sizeof(e2ksniff_errbuf) -1,
				  "There is no user '%s'",
				  unpriv_user);
			return -1;
		} 
		/* Change GID */
		if ( setgid(pw->pw_gid) != 0 ){
			snprintf( e2ksniff_errbuf,
				 sizeof(e2ksniff_errbuf) -1,
				 "Cannot change GID: %s",
				 strerror(errno) );
			return -1;
		}
		/* Clean the supplementary group ID list*/
		if ( setgroups(0,NULL) != 0 ) {
			snprintf( e2ksniff_errbuf,
				  sizeof(e2ksniff_errbuf) -1,
				  "Could not clen the supplementary group IDs list");
			return -1;
			
		}
		/* Finally, change the UID*/
		if ( setuid(pw->pw_uid) != 0 ){
			snprintf( e2ksniff_errbuf,
				 sizeof(e2ksniff_errbuf) -1,
				 "Cannot change UID: %s",
				 strerror(errno) );
			return -1;
		}		
		/* Am I still a superuser ? 
		 * unpriv_user must be a superuser then. */
		if ( (getuid() == 0) || (getgid() == 0) ) {
			snprintf( e2ksniff_errbuf,
				  sizeof(e2ksniff_errbuf) -1,
				  "%s is a superuser - can't drop privileges by impersonating a superuser: is nonsense, dude!", unpriv_user);
			return -1;
		}
	} 
	
	/* Success */
	return 0;
}

/*void syslog_drops(void)*/
/*{*/
/*        struct pcap_stat stat;*/

/*        if (is_sniffing) {*/
/*               if (pcap_descriptor == NULL) {*/
/*                       pcap_descriptor = nids_getdesc();*/
/*               }*/
/*                pcap_stats( pcap_descriptor , &stat);*/
/*                syslog( nids_params.syslog_level,*/
/*                        " ==UDP== Statistics: Droped Packets: %i, Query Answer Received: %u, Received Packtes: %i",*/
/*                        stat.ps_drop,*/
/*                        n_queries,*/
/*                        stat.ps_recv);*/
/*                |+ Eu não confio mais em nada! E chega de comentários*/
/*                 * em inglês!+|*/
/*                fprintf( stdout,*/
/*                         " ==UDP== Statistics: Droped Packets: %i, Active Connections: %u, Received Packtes: %i\n",*/
/*                         stat.ps_drop,*/
/*                        n_queries,*/
/*                        stat.ps_recv);*/
/*        }*/
/*}*/

/* ********************************************************************  
 * Main program
 * ******************************************************************** */

int main(int argc, char* argv[])
{
	
	/* Initial local setup - counters, syslog, etc */
	n_queries = 0;
	is_sniffing = 0;
	next_syslog_report_time = time(NULL);
	pcap_descriptor = NULL; /* setted @ syslog_drops() */
	openlog("e2ksniff", 0, LOG_LOCAL0);
	
	/* Setup libNIDS - defaults */
	nids_params.device = "any";
	/* Just udp from known edonkey udp server ports*/
	//nids_params.pcap_filter = "udp src port (4665 or 4246 or 3310 or 4650)";
	nids_params.one_loop_less = 0; /* We depend of this semantic */
	nids_params.scan_num_hosts = 0; /* Turn port-scan detection off */
	nids_params.no_mem = out_of_memory_callback;
	nids_params.n_hosts=1024*16; /* FIXME value too small? */
	nids_params.n_tcp_streams = 4; /* Low 'cuz there ain't a TCP sniffer */ 
	nids_params.sk_buff_size = 1024*64;

	/* Load recorded trace-file or sniff the network?*/
	if (argc > 1){
		nids_params.device = NULL;
		nids_params.filename = argv[1];
		fprintf(stdout," ==UDP== Loading trace file: %s\n",nids_params.filename );
		is_sniffing = 0;
	} else {
		fprintf(stdout," ==UDP== No tracefile given. Sniffing from the network.\n");
		is_sniffing = 1;
	}

	/* Start libNIDS engine */
	if (!nids_init()) {
		fprintf(stderr, " ==UDP== ERROR: libNIDS error: %s\n", nids_errbuf);
		exit(1);
	}

	/*  DROP PRIVILEGES !!!!  */
	if( (is_sniffing) && 
	    (drop_privilages(UNPRIV_USER) != 0) ){
		fprintf( stderr, " ==UDP== ERROR: Could not drop privileges: %s\n",
			e2ksniff_errbuf);
		exit(1);
	} else {
		fprintf( stdout,
			 " ==UDP== Droped privilages. Impersonating '%s'\n",
			 UNPRIV_USER);
	}

	/* Be nice! :-) */
	if( nice(UDP_NICE_INCREMENT) < 0 ){
		fprintf( stderr, " ==UDP== ERROR: Could not change this process priority: %s\n",
			strerror(errno));
		exit(1);
	} else {
		fprintf( stdout,
			 " ==UDP== Changed this process priority. Nice increment of '%i'\n",
			 UDP_NICE_INCREMENT);
	}
	
	
	nids_register_udp(udp_callback);
	
	/* Go, speed racer, go! */
	syslog( nids_params.syslog_level," ==UDP== Sniffing started.");
	fprintf(stdout," ==UDP== Sniffing started.\n");
	nids_run(); /* Loop forever*/

	/* We were not supposed to get here */	
	syslog( nids_params.syslog_level," ==UDP== Sniffing stopped - ERROR?");
	fprintf(stdout," ==UDP== Sniffing stopped - ERROR?\n");
	fprintf(stderr," ==UDP== Sniffing stopped - ERROR?\n");

	return 0;
}
