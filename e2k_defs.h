/**@file e2k_defs.h
 * @brief Common edonkey definitions
 * @author Tiago Alves Macambira
 * @version $Id: e2k_defs.h,v 1.6 2004-02-16 05:39:23 tmacam Exp $
 * 
 */


#define EDONKEY_CLIENT_PORT 4662

#define EDONKEY_PROTO_EDONKEY 0xe3
#define EDONKEY_PROTO_EMULE  0xe5

#define EDONKEY_MSG_FILE_REQUEST 0x58
#define EDONKEY_MSG_REQUEST_PARTS 0x47
#define EDONKEY_MSG_SENDING_PART 0x46

#define EMULE_MSG_DATA_COMPRESSED 0x40

/** The size of <uchar proto><dword pkt_len><uchar msg_type>*/
#define EDONKEY_HEADER_SIZE 6

typedef unsigned long dword;
typedef unsigned short word;
typedef unsigned char byte;

struct e2k_hash_t {
        byte data[16] ; /**< the 16 bytes that make a MD4 hash */
}__attribute__ ((packed));

struct e2k_header_t {
	/** The type of the protocol */
	byte proto;
	dword packet_size;
	byte msg;
}__attribute__ ((packed));

struct e2k_packet_file_request_t {
	struct e2k_header_t header;
	struct e2k_hash_t hash;
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
