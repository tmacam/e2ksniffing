/**@file LogParser.h
 * @brief LogParser - um XML-Like parser para os logs do e2ksniffing
 * @author Tiago Alves Macambira <tmacam () dcc ufmg br>
 * @version $Id: LogParser.h,v 1.1 2004-05-06 06:54:00 tmacam Exp $
 */
#ifndef __LOG_PARSER_H__
#define __LOG_PARSER_H__

#include <iostream>
#include <string>
#include <utility>

using std::string;
using std::istream;
using std::pair;
using std::istringstream;


typedef pair<unsigned long int,unsigned long int> offset_t;

class LogParser{
	istream& file;
	inline void process_line(string& line);
protected:
	virtual void onSendingPart(  string& hash,  offset_t& offset) = 0;
	virtual void onSendingCompressed(  string& hash,  offset_t& offset) = 0;
public:
	static void get_hash(istream& iss, string& h);
	static void get_offset(istream& iss, offset_t& of);

	LogParser(istream& f): file(f){}

	void parse();
};


#endif /* __LOG_PARSER_H__*/
