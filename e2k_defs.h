/**@file e2k_defs.h
 * @brief Common edonkey definitions
 * @author Tiago Alves Macambira
 * @version $Id: e2k_defs.h,v 1.14 2004-03-26 20:00:49 tmacam Exp $
 *
 * Some parts of this file are from ethereal's packet-edonkey.{c,h}, and
 * thus covered by it's own licence (GPL compat)
 * 
 * (c) Tiago Alves Macambira
 * See COPYING for licence for further license details
 *
 */

#ifndef _E2K_DEFS__H_
#define _E2K_DEFS__H_


/* ********************************************************************  
 * Constants definition
 * ******************************************************************** */

/** The size of the biggest packet we are allowed to process */
#define PACKET_MAXIMUM_SIZE 36000

/** The size of <uchar proto><dword pkt_len><uchar msg_type>*/
#define EDONKEY_HEADER_SIZE 6

#define EDONKEY_CLIENT_PORT 4662

#define EDONKEY_PROTO_EDONKEY 0xe3
#define EDONKEY_PROTO_EMULE  0xc5

#define EDONKEY_MSG_HELLO 0x01
#define EDONKEY_MSG_HELLO_ANSWER 0x4c
#define EDONKEY_MSG_FILE_REQUEST 0x58
#define EDONKEY_MSG_NO_SUCH_FILE 0x48
#define EDONKEY_MSG_FILE_REQUEST_ANSWER 0x59
#define EDONKEY_MSG_REQUEST_PARTS 0x47
#define EDONKEY_MSG_SENDING_PART 0x46
#define EDONKEY_MSG_FILE_STATUS 0x50 
#define EDONKEY_MSG_QUEUE_RANK 0x5c

#define EMULE_MSG_HELLO	0x01
#define EMULE_MSG_HELLO_ANSWER	0x02
#define EMULE_MSG_DATA_COMPRESSED 0x40
#define EMULE_MSG_QUEUE_RANKING 0x60


/* EDONKEY META TAG TYPES */
#define EDONKEY_MTAG_UNKNOWN             0x00
#define EDONKEY_MTAG_HASH                0x01
#define EDONKEY_MTAG_STRING              0x02
#define EDONKEY_MTAG_DWORD               0x03
#define EDONKEY_MTAG_FLOAT               0x04
#define EDONKEY_MTAG_BOOL                0x05
#define EDONKEY_MTAG_BOOL_ARRAY          0x06
#define EDONKEY_MTAG_BLOB                0x07

/* EDONKEY SPECIAL TAGS */
#define EDONKEY_STAG_UNKNOWN             0x00
#define EDONKEY_STAG_NAME                0x01
#define EDONKEY_STAG_SIZE                0x02
#define EDONKEY_STAG_TYPE                0x03
#define EDONKEY_STAG_FORMAT              0x04
#define EDONKEY_STAG_COLLECTION          0x05
#define EDONKEY_STAG_PART_PATH           0x06
#define EDONKEY_STAG_PART_HASH           0x07
#define EDONKEY_STAG_COPIED              0x08
#define EDONKEY_STAG_GAP_START           0x09
#define EDONKEY_STAG_GAP_END             0x0a
#define EDONKEY_STAG_DESCRIPTION         0x0b
#define EDONKEY_STAG_PING                0x0c
#define EDONKEY_STAG_FAIL                0x0d
#define EDONKEY_STAG_PREFERENCE          0x0e
#define EDONKEY_STAG_PORT                0x0f
#define EDONKEY_STAG_IP                  0x10
#define EDONKEY_STAG_VERSION             0x11
#define EDONKEY_STAG_TEMPFILE            0x12
#define EDONKEY_STAG_PRIORITY            0x13
#define EDONKEY_STAG_STATUS              0x14
#define EDONKEY_STAG_AVAILABILITY        0x15
#define EDONKEY_STAG_QTIME               0x16
#define EDONKEY_STAG_PARTS               0x17

/* EMULE SPECIAL TAGS */
#define EMULE_STAG_COMPRESSION         0x20
#define EMULE_STAG_UDP_CLIENT_PORT     0x21
#define EMULE_STAG_UDP_VERSION         0x22
#define EMULE_STAG_SOURCE_EXCHANGE     0x23
#define EMULE_STAG_COMMENTS            0x24
#define EMULE_STAG_EXTENDED_REQUEST    0x25
#define EMULE_STAG_COMPATIBLE_CLIENT   0x26



/* ********************************************************************  
 * Protocol structures and typedefs 
 * ******************************************************************** */

typedef unsigned long dword;
typedef unsigned short word;
typedef unsigned char byte;

struct e2k_hash_t {
        byte data[16] ; /**< the 16 bytes that make a MD4 hash */
}__attribute__ ((packed));

struct e2k_string_t {
	word length; /**< the length of the string*/
	byte str_data; /**< the contents of the string (use it as an array)*/
}__attribute__ ((packed));

struct e2k_metalist_t{
	/* <Meta tag list> = <dword # of tags><Meta tag>* */
	dword length;
	byte data; /*assume 'data' as an array*/
}__attribute__((packed));

struct e2k_metalist_tag_t{
	byte type;
	struct e2k_string_t name;
}__attribute__((packed));

struct e2k_client_info_t{
	/* <Client hash> <Client ID> <Port> <*Meta* list> */
	struct e2k_hash_t client_hash;
	dword client_id;
	word port;
	struct e2k_metalist_tag_t meta_tag_list;
}__attribute__((packed));

struct e2k_header_t {
	/** The type of the protocol */
	byte proto;
	dword packet_size;
	byte msg;
}__attribute__ ((packed));

struct e2k_packet_hello_t {
	struct e2k_header_t header;
	struct e2k_client_info_t client_info;
}__attribute__ ((packed));

struct e2k_packet_hello_client_t {
	struct e2k_header_t header;
	byte clienthash_size;
	struct e2k_client_info_t client_info;
}__attribute__ ((packed));

struct e2k_packet_generic_hash_t {
	struct e2k_header_t header;
	struct e2k_hash_t hash;
}__attribute__ ((packed));

struct e2k_packet_file_request_answer_t {
	struct e2k_header_t header;
	struct e2k_hash_t hash;
	struct e2k_string_t filename;
}__attribute__ ((packed));

struct e2k_packet_request_parts_t {
	struct e2k_header_t header;
	struct e2k_hash_t hash;
	dword start_offset_1;
	dword start_offset_2;
	dword start_offset_3;
	dword end_offset_1;
	dword end_offset_2;
	dword end_offset_3;
}__attribute__ ((packed));

struct e2k_packet_sending_part_t {
	struct e2k_header_t header;
	struct e2k_hash_t hash;
	dword start_offset;
	dword end_offset;
}__attribute__ ((packed));

struct e2k_packet_emule_data_compressed_t{
	struct e2k_header_t header;
	struct e2k_hash_t hash;
	dword start_offset;
	dword packed_len;
}__attribute__ ((packed));

/*<HASH><word len><char[(len+7)/8] data>*/
struct e2k_packet_file_status_t {
	struct e2k_header_t header;
	struct e2k_hash_t hash;
	word len;
	byte bitmap; /*assume bitmap as an array*/
}__attribute__ ((packed));

struct e2k_packet_queue_rank_t {
	struct e2k_header_t header;
	dword rank;
}__attribute__ ((packed));

struct e2k_packet_emule_hello_t {
	struct e2k_header_t header;
	/* <2 Byte Version><*Meta* tag list> */
	word version;
	struct e2k_metalist_t meta_tag_list;
}__attribute__ ((packed));

struct e2k_packet_emule_queue_ranking_t {
	struct e2k_header_t header;
	word rank;
}__attribute__ ((packed));


#endif /* ifndef _E2K_DEFS__H_ */
