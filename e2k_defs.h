/**@file e2k_defs.h
 * @brief Common edonkey definitions
 * @author Tiago Alves Macambira
 * @version $Id: e2k_defs.h,v 1.4 2004-02-12 13:42:39 tmacam Exp $
 * 
 */


#define EDONKEY_CLIENT_PORT 4662
#define EDONKEY_FILE_REQUEST_OPCODE 0x58
#define EDONKEY_REQUEST_PARTS_OPCODE 0x47

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
