#include <iostream>
#include <fstream>
#include <string>
#include <iterator>
#include <algorithm>

#include "ByteHitParser.h"

using namespace std;


void create_fraghash_from_maxsizes( ifstream& file, fileid_frags_hash_t& h,
		int frag_len)
{
	

	string hash;
	offset_count_t maxsize;
	int i = 0;
	int j = 0;

	while(! file.eof()){
		file.width(32);
		file >> hash;
		file >> maxsize;
		h[hash] = frag_hit_list_t( maxsize/frag_len + 1, 0);

		// give us some Idea of what is happening
		i++;
		if ( i > 1000){
			j++;
			cout << "\t"<<j<<"000 arquivos ...\n";
			i=0;
		}
	}
}

void print_byte_hit(ofstream& output, const string& hash, 
		const frag_hit_list_t& frags )
{
	output << hash  << " ";
	ostream_iterator<offset_count_t> oo(output," ");
	copy(frags.begin(),frags.end(),oo);
	output << endl;
}

int main (int argc, char* argv[])
{
	unsigned int frag_size = 1024*20;
	
	if (argc < 4){
		std::cout <<"Usage: byte_hit_rate log.txt max_sizes.txt hash_hit.txt\n";
		exit(1);
	}
	
	// Open all files - let's fail in one single place
	ifstream log_s(argv[1],std::ios::in);
	if ( !log_s.good()){
		std::cerr << "Error opening file: "<< argv[1] << std::endl;
		exit(1);
	}
	ifstream max_sizes_s(argv[2],std::ios::in);
	if ( !max_sizes_s.good()){
		std::cerr << "Error opening file: "<< argv[2] << std::endl;
		exit(1);
	}
	ofstream output_s(argv[3],std::ios::out);
	if ( !output_s.good()){
		std::cerr << "Error opening file "<< argv[3] << std::endl;
		exit(1);
	}

	std::cout << "Seting up auxiliary structures ...\n";
	std::cout.flush();
	fileid_frags_hash_t hit_hash(15000);
	create_fraghash_from_maxsizes( max_sizes_s, hit_hash, frag_size);
	std::cout << "done.\n";

	std::cout << "Parsing began...\n";
	ByteHitParser parser(log_s, hit_hash, frag_size);
	parser.parse();
	std::cout << "Parsing done... Writing the byte-hit-rate-thing\n";
	for( fileid_frags_hash_t::const_iterator h = parser.hit_hash.begin();
	     h != parser.hit_hash.end();
	     ++h)
	{
		print_byte_hit(output_s, h->first, h->second);
	}

	return 0;
}
