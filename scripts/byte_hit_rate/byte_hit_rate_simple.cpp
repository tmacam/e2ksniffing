#include <iostream>
#include <fstream>
#include <string>
#include <iterator>
#include <algorithm>
#include <cstdlib>

#include "ByteHitParser.h"

using namespace std;


void print_byte_hit(ofstream& output, const frag_hit_list_t& frags )
{
	ostream_iterator<offset_count_t> oo(output," ");
	copy(frags.begin(),frags.end(),oo);
	output << endl;
}

void parse_file(istream& log, frag_hit_list_t& fragments, 
		unsigned int frag_size)
{
	unsigned int offset;
	unsigned int len;

	int line = 0;
	int to_next_announce = 1000;

	while(! log.eof() ){
		log >> offset;
		log >> len;
		updateByteHits(fragments,offset,len,frag_size);
		
		line++;
		to_next_announce--;
		if (to_next_announce < 0){
			to_next_announce = 1000;
			std::cout << "\t" << line << std::endl;
		}
	}
}

int main (int argc, char* argv[])
{
	unsigned int frag_size = 0;
	unsigned int file_size = 0;
	
	if (argc < 5){
		std::cout<<"Usage: byte_hit_rate log.txt bytehit.txt file_size frag_size\n";
		exit(1);
	}
	
	// Open all files - let's fail in one single place
	ifstream log_s(argv[1],std::ios::in);
	if ( !log_s.good()){
		std::cerr << "Error opening file: "<< argv[1] << std::endl;
		exit(1);
	}

	ofstream output_s(argv[2],std::ios::out);
	if ( !output_s.good()){
		std::cerr << "Error opening file "<< argv[2] << std::endl;
		exit(1);
	}
	
	file_size = atoi(argv[3]);
	if ( file_size < 1){
		std::cerr << "Empty file - nothing to do" << std::endl;
		exit(1);
	}

	frag_size = atoi(argv[4]);
	if ( frag_size < 512){
		std::cerr << "Fragment size too small: ";
		std::cerr << frag_size << std::endl;
		exit(1);
	}

	std::cout << "Seting up auxiliary structures ... ";
	std::cout.flush();
	frag_hit_list_t fragments(file_size/frag_size + 1, 0);
	std::cout << "done.\n";

	std::cout << "Parsing began ...\n";
	parse_file(log_s, fragments, frag_size);
	std::cout << "Parsing done.\n";

	std::cout << "Writing the byte-hit-rate-thing ... ";
	std::cout.flush();
	print_byte_hit(output_s, fragments);
	std::cout << "done.\n";

	return 0;
}
