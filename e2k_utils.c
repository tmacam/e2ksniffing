/**@file e2k_utils.c
 * @brief Utility functions
 * @author Tiago Alves Macambira
 * @version $Id: e2k_utils.c,v 1.4 2004-03-21 02:29:07 tmacam Exp $
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "e2k_utils.h"


const char *address_str(struct tuple4 addr)
{
	static char buf[256];
	strncpy(buf, inet_ntoa(*((struct in_addr *)&(addr.saddr))), 255);
	snprintf(buf + strlen(buf), 255, ":%i,", addr.source);
	strncpy(buf + strlen(buf), inet_ntoa(*((struct in_addr *)&(addr.daddr))),256);
	snprintf(buf + strlen(buf), 255, ":%i", addr.dest);
	return buf;
}

unsigned char* hexstr (unsigned char *data, unsigned int len)
{
        unsigned char* result = NULL;
        int i = 0;

        /* hex of one  byte takes 2 chars. +1 for the ending '/0' */
        result = (char*)calloc( (2*len + 1), sizeof(char));
        if (result == NULL){
                return result;
        }
	
        for(i = 0; i < len; i++) {
                sprintf(&result[2*i], "%02x", data[i]);
        }

        return result;
}

unsigned char* asprintf_hash(struct e2k_hash_t* hash )
{
	byte* hash_data = hash->data; /* Saving 16 ptrs. indirections*/
	unsigned char* result = NULL;
	int ret = 0;

	ret = asprintf(&result,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		hash_data[0], hash_data[1], hash_data[2], hash_data[3], 
		hash_data[4], hash_data[5], hash_data[6], hash_data[7],
		hash_data[8], hash_data[9], hash_data[10],hash_data[11],
		hash_data[12],hash_data[13],hash_data[14],hash_data[15]);
	if (ret < 0){
		return NULL;
	} else {
		return result;
	}

}

unsigned char* strtimestamp()
{
	static unsigned char timestamp[25];
	time_t now;

	time(&now);
	strftime(timestamp,24,"%s",localtime(&now));

	return timestamp;
}

int fprintf_e2k_string(FILE* stream, struct e2k_string_t* netstring)
{
	return fprintf( stream,
			"%.*s",
			(int)(netstring->length),
			(char*)&(netstring->str_data));
}

int fprintf_e2k_hash(FILE* stream, struct e2k_hash_t* hash )
{
	byte* hash_data = hash->data; /* Saving 16 ptrs. indirections*/

	return fprintf(stream,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		hash_data[0], hash_data[1], hash_data[2], hash_data[3], 
		hash_data[4], hash_data[5], hash_data[6], hash_data[7],
		hash_data[8], hash_data[9], hash_data[10],hash_data[11],
		hash_data[12],hash_data[13],hash_data[14],hash_data[15]);
}

int fprintf_e2k_hex (FILE* stream,unsigned char *data, unsigned int len)
{
        int i = 0;
	int result=0;

        for(i = 0; i < len; i++) {
                result=fprintf(stream, "%02x", data[i]);
		if (result < 0){
			break;
		}
        }

        return result;
}
