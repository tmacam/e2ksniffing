/**@file e2k_zip.h
 * @brief Structures and fuctions to handle emule compressed data packets
 * @author Tiago Alves Macambira
 * @version $Id: e2k_zip.h,v 1.3 2004-08-31 23:35:50 tmacam Exp $
 *
 * Some parts of this file are from aMule 1.2.6 DownloadClient.cpp , and
 * thus covered by it's own licence (GPL compat)
 * 
 * (c) Tiago Alves Macambira
 * See COPYING for licence for further license details
 *
 */

#ifndef __E2K_ZIP_H__
#define __E2K_ZIP_H__ 1

#include <zlib.h>
#include "e2k_defs.h"


#define E2K_ZIP_ERR -1
#define E2K_ZIP_OK 0
#define E2K_ZIP_FINISHED 1

/**@brief Keeps zlib state and edonkey-data related to a REQUEST PARTS packet
 * and to the  EMULE COMPRESSED DATA packets it received as answer.
 * 
 * Nnotice that in_use and start are independent. As a matter of fact, you 
 * should update the value of start everytime a REQUEST PARTS messege is
 * received, no matter if a e2k_zip_state_t is in_use or not.
 * 
 */
typedef struct e2k_zip_state_t{
	/** Is this structure being used? Has it allocated anything? */
	int in_use;
	/** Start offset of the REQUEST PARTS parts that originated this
	 * stream of compressed data (broken into EMULE COMPRESSED DATA 
	 * packets). Used for bookkeeping and sanity check - so set it
	 * correctly.
	 *
	 * Notice that as of emule's code, the change of a start signals
	 * that a new compress2-zstream follow i.e., yuo should call
	 * e2k_zip_destroy.
	 */
	dword	start;
	/** Should this stream be ignored? */
	int ignore;
	/** zlib's z_stream - keeps state information about the unzipping
	 * process*/
	z_stream zs;
	/** the buffer where data will be unzipped. Allocated by e2k_zip_init
	 * and destroyed by e2k_zip_destroy */
	byte* unzipped_buf;
	/** The length of the buffer. */
	dword unzipped_buf_len;
	/** the ammount of currently unzipped data present in the buffer */
	dword total_unzipped;
} e2k_zip_state_t;






/**@brief Setup and initialize decrompression structures
 *
 * @param _zstate the decompression-state-tracking thingie to be initialized
 * @param start the position of the chunck of data that was
 * 	compressed and broken into various EMULE COMPRESSED DATA packets
 */
int e2k_zip_init(e2k_zip_state_t* zip_state);


/**@brief Destroy all pending data related to a zip_state
 *
 * This function can be called multiple times, even with already-destroyed
 * e2k_zip_state_t .
 *
 */
int e2k_zip_destroy(e2k_zip_state_t* zip_state);


/**@brief unzip a chunk of data
 *
 * @notice This function overwrites the provided e2k_zip_state_t's
 * unzipped_buf and unzipped_buf_len at each call.
 *
 * @param zip_state Zip_state realted to a REQUEST PARTS and to the
 * 		group of EMULE COMPRESSED DATA that followed it
 * @param len_unziped returns the number of bytes unzipped in this call
 * @param zipped_buf_len length of the buffer with the data to be unzipped
 * @param zipped_buf buffer with the data to be unzipped
 *
 * @param i_recursion MUST BE SET TO 0!
 *
 * @return E2K_ZIP_OK or E2K_ZIP_FINISHED if things went ok. The latter 
 * 	   means that the stream is finished and you can destroy this
 * 	   e2k_zip_state_t after you read its uncompressed data... If
 * 	   the streams if found corrupted of if another error is found
 * 	   E2K_ZIP_ERR is returned.
 *
 */
int e2k_zip_unzip(e2k_zip_state_t* zip_state, dword* len_unzipped,
		dword zipped_buf_len, byte* zipped_buf, int i_recursion );

#endif /* __E2K_ZIP_H__ */
