#include <iostream>
#include <string>

#include "MaxOffsetParser.h"

int main (int argc, char* argv[])
{
	typedef fileid_int_hash_t::const_iterator bh_hashes_t;
	
	MaxOffsetParser parser(std::cin);

	parser.parse();
	for(bh_hashes_t i = parser.h.begin(); i != parser.h.end(); ++i){
		std::cout << i->first  << "\t" << i->second << std::endl;
	}

	return 0;
}
