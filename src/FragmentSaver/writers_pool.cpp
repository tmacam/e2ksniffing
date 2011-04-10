#include "writers_pool.h"
#include "WritersPool.h"
#include <string>
#include <exception>


/* *****************************************************************
 * 		-=- Public declarations -=- 
 * ***************************************************************** */ 


int writers_pool_init(writers_pool_t* pool, 
		const char* base_path)
{
	try {
		WritersPool* _pool = new WritersPool(base_path);
		*pool = (writers_pool_t)_pool;
	} catch (std::exception& e) {
		return -1;
	}

	return 0;
}

int writers_pool_destroy (const writers_pool_t pool)
{
	WritersPool* _pool = (WritersPool*)pool;

	if( _pool == NULL ){ return -1; } // Wouldn't an assert() be better?
	
	try {
		delete _pool;
	} catch (std::exception& e) {
		return -1;
	}

	return 0;
		
}

writers_pool_writer_t writers_pool_writer_get(
		const writers_pool_t pool, const char* file_id )
{
	WritersPool* _pool = (WritersPool*)pool;
	FragmentedFileWriter* _writer = NULL;

	if( _pool == NULL ){ return NULL; } // Wouldn't an assert() be better?

	try {
		_writer = _pool->getWriter(std::string(file_id));
	} catch (std::exception& e) {
		_writer = NULL;
	}

	return _writer;

}

int writers_pool_writer_release(const writers_pool_t pool,
		const char* file_id)
{
	WritersPool* _pool = (WritersPool*)pool;

	if( _pool == NULL ){ return -1; } // Wouldn't an assert() be better?

	try {
		_pool->releaseWriter(std::string(file_id));
	} catch (std::exception& e) {
		return -1;
	}

	return 0;
}


int writers_pool_writer_write( const writers_pool_writer_t writer,
		unsigned int start, unsigned int end, const char* buf)
{
	FragmentedFileWriter* _writer = (FragmentedFileWriter*)writer;

	if( _writer == NULL ){ return -1; } // Wouldn't an assert() be better?

	try {
		_writer->write(start,end,buf);
	} catch (std::exception& e) {
		return -1;
	}

	return 0;
}

/* EOF */
