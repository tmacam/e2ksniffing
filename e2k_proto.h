/**@file e2k_proto.h
 * @brief edonkey protocol handling funtions
 * @author Tiago Alves Macambira
 * @version $Id: e2k_proto.h,v 1.1 2004-03-11 20:13:49 tmacam Exp $
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

#ifndef _E2K_PROTO__H_
#define _E2K_PROTO__H_

/* ********************************************************************  
 * 
 * ******************************************************************** */

/**@brief Process a sniffed edonkey packet
 *
 * @param pkt_data the edonkey packet raw data
 * 
 * @param addr_tuple pointer to a structure with  addres/port of the
 * two endpoints of the connection from where the packet was sniffed.
 */
void handle_edonkey_packet(int is_server, char *pkt_data, char *address_str);

#endif /*_E2K_PROTO__H_*/
