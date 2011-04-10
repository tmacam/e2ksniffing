#ifndef __FRAGMENTED_FILE_WRITER_H__
#define __FRAGMENTED_FILE_WRITER_H__

#include "IntervalMap.h"
#include <string>
#include <cstdio>
#include <fstream>


class FragmentedFileWriter{
private:
	void turnExceptionsOn(std::ios& stream);
protected:
	std::string file_name;
	std::ofstream file_stream;
	IntervalMap intervals;

public:

	FragmentedFileWriter(const std::string& fileid,
			const std::string& filepath = "./");

	~FragmentedFileWriter();
	
	/**@brief Writes (end-start) bytes from buf in file's range 
	 * [start,end) IFF this range was not already written.
	 */ 
	void write(const IntervalMap::integral_type start,
			const IntervalMap::integral_type end,
			const char* buf);
	
	/**@brief flush file and interval data cotents to disk*/
	void flush();

};

#endif // __FRAGMENTED_FILE_WRITER_H__
