#include "FragmentedFileWriter.h"
#include <algorithm>
#include <iterator>
#include <assert.h>


void FragmentedFileWriter::turnExceptionsOn(std::ios& stream)
{
	stream.exceptions( std::ios_base::badbit|std::ios_base::failbit);
}


//FIXME :  s/std::cerr//throw exception
//FIXME WTF - be a man and use write(2)
FragmentedFileWriter::FragmentedFileWriter( const std::string& fileid,
		const std::string& filepath ) :
		file_name(filepath + "/" + fileid)
{
	// Get the intervals from the file
	std::string intervals_filename = file_name + ".intervals" ;
	std::ifstream saved_intervals(intervals_filename.c_str());
	if(saved_intervals){
		intervals.serialize(saved_intervals);
	}
	saved_intervals.close(); // why left this one open?

	// open the file
	turnExceptionsOn(file_stream);
	file_stream.sync_with_stdio(false);
	file_stream.open(file_name.c_str(), std::ios::ate | std::ios::binary);
	if(!file_stream){
		std::cerr << "Could not open file " << file_name << std::endl;
	}
}

FragmentedFileWriter::~FragmentedFileWriter()
{
	flush();
	file_stream.close();
}

void FragmentedFileWriter::write(const IntervalMap::integral_type start,
		const IntervalMap::integral_type end, const char* buf)
{
	assert(end >= start);

	if ( intervals.insert(start,end) != intervals.ZERO ) {
		file_stream.seekp(start,std::ios_base::beg);
		file_stream.write(buf, end-start);
	}
}

//FIXME :  s/std::cerr//throw exception
void FragmentedFileWriter::flush()
{
	// flush the file's contents first
	file_stream.flush();

	// write the interval data
	std::string intervals_filename = file_name + ".intervals" ;
	std::ofstream saved_intervals(intervals_filename.c_str());
	if(!saved_intervals){
		std::cerr << "Could not save intervals data for file " <<
				file_name << std::endl;
	} else {
		turnExceptionsOn(saved_intervals);
		intervals.serialize(saved_intervals);
	}
	saved_intervals.close(); // why left this one open
}
