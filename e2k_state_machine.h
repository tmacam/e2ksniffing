/**@file e2k_state_machine.h
 * @brief edonkey state-machine control function
 * @author Tiago Alves Macambira
 * @version $Id: e2k_state_machine.h,v 1.1 2004-03-11 20:13:50 tmacam Exp $
 * 
 * 
 * Based on sample code provided with libnids and copyright (c) 1999
 * Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
 * See the file COPYING from libnids for license details.
 *
 *
 * (c) Tiago Alves Macambira
 * See COPYING for licence for further license details
 *
 */

#ifndef _E2K_STATE_MACHINE__H_
#define _E2K_STATE_MACHINE__H_

#include "nids.h"

#include "main.h"


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
inline int get_next_packet_offset(int current_offset, int current_packet_len);

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
			    half_conn_state_t *state);

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
			    half_conn_state_t *state);



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
			    half_conn_state_t *state);

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
			    half_conn_state_t *state);


#endif /*_E2K_STATE_MACHINE__H_*/
