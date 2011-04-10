#include "WritersPool.h"
#include <assert.h>
#include <iostream>


const WritersPool::writer_ref_t WritersPool::NULL_REF = writer_ref_t(NULL,0);


WritersPool::~WritersPool()
{	
	writer_ref_t ref;
	writers_hash_t::iterator i;

	//Destroy all the open writers
	for(i = pool.begin(); i != pool.end(); ++i){
		ref = i->second;
		delete ref.first;
		std::cout << "(~WritersPool) Destruction of Writer - ID " << i->first << std::endl;
	}
}

FragmentedFileWriter* WritersPool::getWriter(const std::string& file_id)
{
	writer_ref_t ref;
	
	if ( (ref = pool[file_id])  == NULL_REF) {
		// There isn't a FFW for this FileID - Creating one
		ref.first = new FragmentedFileWriter(file_id,base_path);
	}

	++ref.second; // ref-count
	pool[file_id] = ref;
	
	return ref.first;

}
	
void WritersPool::releaseWriter(const std::string& file_id)
{
	writer_ref_t ref;
	
	ref = pool[file_id];
	assert(ref != NULL_REF);
	
	ref.second--; // ref-count	
	if ( ref.second < 1){
		delete ref.first;
		pool.erase(file_id);
		std::cout << "(releaseWriter) Destruction of Writer - ID " << file_id << std::endl;
	} else {
		ref.first->flush();
		std::cout << "(releaseWriter) Decremented reference of Writer - ID " << 
			file_id << ", " << ref.second << " left"<< std::endl;
		pool[file_id] = ref;
	}
}
