/**@file e2k_zip.c
 * @brief Structures and fuctions to handle emule compressed data packets -
 * 	  Implementation
 * @author Tiago Alves Macambira
 * @version $Id: e2k_zip.c,v 1.5 2004-08-31 23:35:50 tmacam Exp $
 *
 * Some parts of this file are from aMule 1.2.6 DownloadClient.cpp , and
 * thus covered by it's own licence (GPL compat)
 * 
 * (c) Tiago Alves Macambira
 * See COPYING for licence for further license details
 *
 */

#include <string.h>		/* for bzero, memcpy, etc... */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "e2k_zip.h"



/* ********************************************************************  
 *  Private functions and declarations
 * ******************************************************************** */

#define E2K_ZIP_BLOCK_SIZE 184320

static inline void duplicate_output_buffer( e2k_zip_state_t* zip_state,
		dword* len_unzipped, dword zipped_buf_len, z_stream* zs )
{
	byte* temp = NULL;
	dword newly_unzipped_data_len = 0;
	
	dword new_length = zip_state->unzipped_buf_len *= 2;
	if (new_length == 0) {
		new_length = zipped_buf_len * 2;
	}

	newly_unzipped_data_len = zs->total_out - zip_state->total_unzipped;	
	
	/* Copy any data that was successfully unzipped to new array */
	temp = malloc(new_length);
	assert(temp != NULL);
	assert( newly_unzipped_data_len <= new_length );
	memcpy( temp, (zip_state->unzipped_buf), newly_unzipped_data_len );
	free(zip_state->unzipped_buf);
	zip_state->unzipped_buf = temp;
	zip_state->unzipped_buf_len = (*len_unzipped) = new_length;

	// Position stream output to correct place in new array
	zs->next_out = zip_state->unzipped_buf + newly_unzipped_data_len ;
	zs->avail_out = new_length - newly_unzipped_data_len;
}


/* ********************************************************************  
 *  Public functions
 * ******************************************************************** */


int e2k_zip_destroy(e2k_zip_state_t* zip_state)
{
	int res = E2K_ZIP_OK;

	/* Destroy any previous state */
	if (zip_state->in_use) {
		if (inflateEnd( &(zip_state->zs) ) != Z_OK){
			res = E2K_ZIP_ERR;
		};
		if (zip_state->unzipped_buf){
			free(zip_state->unzipped_buf);
			zip_state->unzipped_buf = NULL;
		}
		zip_state->in_use = 0;
	} 

	/* Job done... Move on...*/
	return res;
}

int e2k_zip_init(e2k_zip_state_t* zip_state)
{
	
	if (zip_state->in_use){
		return E2K_ZIP_ERR;
	}
	
	/* Clear state configuration to default values */
	bzero(zip_state,sizeof(e2k_zip_state_t));

	/* Set it up*/
	zip_state->in_use = 1;
	/* zip_state->start  -=- Should NOT BE set here, but by the callee */
	zip_state->unzipped_buf_len = E2K_ZIP_BLOCK_SIZE + 300;
	zip_state->unzipped_buf = malloc(zip_state->unzipped_buf_len); 
	if(zip_state->unzipped_buf == NULL){
		e2k_zip_destroy(zip_state);
		return E2K_ZIP_ERR;
	}
	
	/* Initialise stream values -=- Done by calloc/bzero
	 * zip_state->ignore = 0;
	 * zip_state->zs.zalloc = (alloc_func)0;
	 * zip_state->zs.zfree = (free_func)0;
	 * zip_state->zs.opaque = (voidpf)0;
	 * zip_state->zs.next_in = 0;
	 * zip_state->zs.avail_int = 0;
	 */
	zip_state->zs.next_out = zip_state->unzipped_buf;
	zip_state->zs.avail_out = zip_state->unzipped_buf_len;

	if ( inflateInit(&(zip_state->zs)) != Z_OK){
		e2k_zip_destroy(zip_state);
		return E2K_ZIP_ERR;
	};
			
	return E2K_ZIP_OK;
	
}


int e2k_zip_unzip(e2k_zip_state_t* zip_state, dword* len_unzipped,
		dword zipped_buf_len, byte* zipped_buf, int i_recursion )
{
	/* Default values - assume everything fails*/
	z_stream* zs = NULL;
	int err = Z_DATA_ERROR;
	dword amount_unzipped_here = 0; /* how mutch did this call unzipped?*/
	(*len_unzipped) = 0;

	assert(zip_state != NULL);

	if (zip_state->ignore){
		return E2K_ZIP_ERR;
	}

	zs = &(zip_state->zs);
	zs->next_in  = zipped_buf;
	zs->avail_in = zipped_buf_len;

	// Only set the output if not being called recursively
	if (i_recursion == 0) {
		zs->next_out = zip_state->unzipped_buf;
		zs->avail_out = zip_state->unzipped_buf_len;
	}

	err = inflate(zs, Z_SYNC_FLUSH);

	assert(zs->total_out >= zip_state->total_unzipped);
	amount_unzipped_here = zs->total_out - zip_state->total_unzipped;

	/* Has zip finished reading all currently available input and writing
	 * all generated output
	 */
	if (err == Z_STREAM_END) {
		/* Got a good result, set the size to the amount unzipped
		 * in this call  (including all recursive calls)
		 */
		(*len_unzipped) = amount_unzipped_here;
		zip_state->total_unzipped = zs->total_out;

		return E2K_ZIP_FINISHED;
	}else if ((err == Z_OK) && (zs->avail_out == 0) && (zs->avail_in != 0)){
		/* Output array was not big enough, call recursively until
		 * there is enough space
		 */
		duplicate_output_buffer( zip_state, len_unzipped,
				zipped_buf_len, zs );
		/*FIXME: remove loggin */
		fprintf(stderr,"e2k_zip_unzip: output enlarged to %lu\n",
				(*len_unzipped) );
		/* ... and try again */
		err = e2k_zip_unzip(zip_state, len_unzipped,
			zipped_buf_len, zipped_buf, i_recursion + 1);
		assert(err == E2K_ZIP_OK);
		if (err == E2K_ZIP_ERR){
			(*len_unzipped) = 0;
		}

		return err; /* Converted to E2K_ZIP_XXX above */
	} else if ((err == Z_OK) && (zs->avail_in == 0)) {
		/* All available input has been processed, everything ok.
		 * Set the size to the amount unzipped in this call
		 * (including all recursive calls)
		 */
		(*len_unzipped) = amount_unzipped_here;
		zip_state->total_unzipped = zs->total_out;

		return E2K_ZIP_OK;
	} else if (err == Z_BUF_ERROR) {
		return E2K_ZIP_OK;
	} else {
		/* Should not get here unless input data is corrupt */
		(*len_unzipped) = 0;
		return E2K_ZIP_ERR;
	}

	assert(1 == 0); /* We should never get here! */
}


/* EOF */

