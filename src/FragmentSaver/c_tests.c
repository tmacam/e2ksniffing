#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "writers_pool.h"


void fatal_error(const char* err)
{
	fprintf(stderr, "ERROR: %s\n", err);
	exit(1);
}

int main()
{
	writers_pool_t pool;
	writers_pool_writer_t writer;
	const char* file_id = "THIS_IS_A_FILE_ID";
	char buf[1024];
	int i=0;

	memset( buf, 0x33, sizeof(buf));

	if ( writers_pool_init(&pool,"/tmp/") == E2K_WRITERS_POOL_ERROR ){
		fatal_error("Could now init an instance of WritersPool");
	}

	if( (writer = writers_pool_writer_get(pool,file_id)) == NULL ){
		fatal_error("could not get a writer instance from the pool");
	}
	
	/* Creating another reference to writer - lost the previous reference */
	if( (writer = writers_pool_writer_get(pool,file_id)) == NULL ){
		fatal_error("could not get a writer instance from the pool");
	}
	
	for(i = 0; i < 1024; i++){
		if ( writers_pool_writer_write( writer,
				(unsigned int)i*1024,
				(unsigned int)(i+1)*1024,
				buf ) == E2K_WRITERS_POOL_ERROR )
		{
			fatal_error("error sending request to writer");
		}
	}

	if ( writers_pool_writer_release(pool,file_id) == 
		E2K_WRITERS_POOL_ERROR )
	{
		fatal_error("Error releasing a writer reference");
	}
	
	if ( writers_pool_destroy(pool) == E2K_WRITERS_POOL_ERROR) {
		fatal_error("Error destroing WritersPool instance");
	}
	
	return 0;
}
