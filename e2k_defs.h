/* 
 * @author Tiago Alves Macambira
 * @version $Id: e2k_defs.h,v 1.2 2004-01-15 03:05:20 tmacam Exp $
 * 
 * 
 * 
 */


/* #define BEEN_HERE do {printf("BEEN HERE: %03i\n",__LINE__);} while(0) */
#define BEEN_HERE do {} while(0)

#define EDONKEY_CLIENT_PORT 4662
#define EDONKEY_FILE_REQUEST_OPCODE 0x58

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
