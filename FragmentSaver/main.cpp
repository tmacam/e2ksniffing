#include "IntervalMap.h"
#include "FragmentedFileWriter.h"
#include "WritersPool.h"
#include <iostream>
#include <exception>
#include <cstring>





int main (int argc, char* argv[])
{
	int i = 0;
	unsigned int start,end;
	char buf[1024];

	memset(buf,0xff,1024);
	std::string file_id="test_id";
	
	try {
		WritersPool pool("/tmp/");
		FragmentedFileWriter* f = pool.getWriter(file_id);
		FragmentedFileWriter* _f = pool.getWriter(file_id);	
		FragmentedFileWriter* _g = pool.getWriter(file_id);				
		for (i = 0; i < 1024 ; ++i){
			start = i*1024;
			end = (i+1)*1024;
			f->write(start, end-100, buf);
			_g->write(end-110, end, buf);
		}
		pool.releaseWriter(file_id);
	} catch (std::exception& e) {
		std::cerr << "Ops!" << e.what() << std::endl;
		return 1;
	}
	
	return 0;
}
