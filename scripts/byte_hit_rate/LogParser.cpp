/**@file LogParser.cpp
 * @brief LogParser - implementation
 * @author Tiago Alves Macambira <tmacam () dcc ufmg br>
 * @version $Id: LogParser.cpp,v 1.1 2004-05-06 06:54:00 tmacam Exp $
 */

#include <sstream>

#include "LogParser.h"

using std::string;
using std::istream;


const string str_send_part = "SENDING PART ";
const int str_send_part_len = str_send_part.length();
const string str_compressed_part = "EMULE COMPRESSED DATA ";
const int str_compressed_part_len = str_compressed_part.length();




void LogParser::get_hash(istream& iss, string& h)
{
	iss.ignore(10,'[');
	iss.width(32);
	iss >> h;
}

void LogParser::get_offset(istream& iss, offset_t& of)
{
	iss.ignore(10,'[');
	iss >> of.first;
	iss.ignore();
	iss >> of.second;
}

void LogParser::process_line(string& line)
{
	unsigned int pos;
	istringstream line_stream;

	string hash;
	offset_t offset;

	if ( (pos = line.find(str_send_part)) != string::npos) {
		pos += str_send_part_len; 	//"SENDING PART "
		line_stream.str(line.substr(pos));
		// Get the fields hash[] offset[]
		get_hash(line_stream,hash);
		get_offset(line_stream,offset);
		onSendingPart(hash,offset);
	} else if ( (pos = line.find(str_compressed_part)) != string::npos) {
		pos += str_compressed_part_len;	 //"Compressed emule data "
		line_stream.str(line.substr(pos));
		// Get the fields hash[] offset[]
		get_hash(line_stream,hash);
		get_offset(line_stream,offset);
		onSendingCompressed(hash,offset);
	}

}

void LogParser::parse()
{
	string line;

	while (! file.eof() ) {
		getline(file,line);
		process_line(line);
	}
	
}



