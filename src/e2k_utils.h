/**@file e2k_utils.h
 * @brief Utility functions
 * @author Tiago Alves Macambira
 * @version $Id: e2k_utils.h,v 1.5 2004-08-18 20:58:01 tmacam Exp $
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

#ifndef _E2K_UTILS__H_
#define _E2K_UTILS__H_


#include "nids.h"

#include "e2k_defs.h"


/**@brief translates a tuple4 struct to a string
 *
 * struct tuple4 contains addresses and port numbers of the TCP connections
 * the following auxiliary function produces a string looking like
 * 10.0.0.1,1024,10.0.0.2,23
 *
 * The string is returned in a statically allocated buffer,  which
 * subsequent calls will overwrite.
 */
const char *address_str(struct tuple4 addr);

/**@brief Converts a given amount of data into its hex-str representation
 *
 * The returned data is dynamically allocated so it is the callers's
 * resposability to free the returned data.
 *
 * @param data the data to be hex-stringyfied
 * @param len the lenth of the data to be hex-stringyfied
 */
unsigned char* hexstr (unsigned char *data, unsigned int len);

/**@brief Converts MD4 hash into a dynamically allocated string
 *
 * This function will "convert" a MD4 hash into its hex-coded string.
 * This string will be dynamic allocated - remember to free it later.
 *
 * @param e2k_hash the MD4 hash
 * @see hash2str
 */
unsigned char* asprintf_hash(const struct e2k_hash_t* hash );

/**@brief Converts MD4 hash into a statically allocated string
 *
 * This function will "convert" a MD4 hash into its hex-coded string.
 * This string will be statically allocated - DON'T DARE FREE IT!
 *
 * @param e2k_hash the MD4 hash
 * @see asprintf_hash
 */
const unsigned char* hash2str(const struct e2k_hash_t* hash );

/**@brief return a timestamp string
 *
 * @warning The return value points to a statically allocated
 * string which might be overwritten by subsequent calls to this function.
 * 
 * @return a static allocated pointer to a string with the current timestamp
 */
unsigned char * strtimestamp();

inline int fprintf_e2k_string(FILE* stream, struct e2k_string_t* netstring);
inline int fprintf_e2k_hash(FILE* stream, struct e2k_hash_t* hash );
inline int fprintf_e2k_hex (FILE* stream,unsigned char *data, unsigned int len);



#endif /*_E2K_UTILS__H_*/
