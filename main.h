/* 
 * @author Tiago Alves Macambira
 * @version $Id: main.h,v 1.1 2004-01-15 02:26:24 tmacam Exp $
 * 
 * 
 * 
 */


/* #define BEEN_HERE do {printf("BEEN HERE: %03i\n",__LINE__);} while(0) */
#define BEEN_HERE do {} while(0)

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

