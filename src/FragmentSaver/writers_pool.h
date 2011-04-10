/**@file writers_pool.h
 * @brief C wrapper functions to C++ objects
 *
 * @see WritersPool
 */
#ifndef __E2K_WRITERS_POOL_H__
#define __E2K_WRITERS_POOL_H__

#define E2K_WRITERS_POOL_OK 0
#define E2K_WRITERS_POOL_ERROR -1

typedef void* writers_pool_t;
typedef void* writers_pool_writer_t;

#ifdef __cplusplus
extern "C" {
#endif

/**@brief Initiate a new WritersPool
 *
 * @return 0 in sucess, -1 otherwise
 */
int writers_pool_init(writers_pool_t* pool, const char* base_path);

/**@brief Destroy a given WritersPool, securely saving all of it's pending
 * data and releasing all of its writers
 *
 * @return 0 in case of success, -1 otherwise;
 */
int writers_pool_destroy (const writers_pool_t pool);

/**@brief Obtains a reference to the writer associated with the given 
 * file_id.
 *
 * @return NULL in case of errors or a reference to a writers_pool_writer_t
 * otherwise.
 */
writers_pool_writer_t writers_pool_writer_get( 
		const writers_pool_t pool,
		const char* file_id);

/**@brief Release the writer associated with the given file_id
 *
 * @return 0 in case of success. -1 otherwise*/
int writers_pool_writer_release( const writers_pool_t pool,
					const char* file_id);


/**@brief Ask the given writer to write the given data into the given
 * range ;-)
 *
 * The range is in the format [start,end).
 *
 * @return 0 in case of success. -1 otherwise*/
int writers_pool_writer_write( const writers_pool_writer_t writer,
						unsigned int start, 
						unsigned int end,
						const char* buf);

#ifdef __cplusplus
} /* extern "C" { */
#endif

#endif /* __E2K_WRITERS_POOL_H__ */
