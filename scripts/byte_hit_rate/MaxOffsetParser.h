#ifndef __MAX_OFFSET_PARSER_H__
#define __MAX_OFFSET_PARSER_H__
/**@file MaxOffsetParser.h
 * @brief Procura o maior offset mencionado em uma troca de arquivos edonkey
 * @author Tiago Alves Macambira <tmacam () dcc ufmg br>
 * @version $Id: MaxOffsetParser.h,v 1.1 2004-05-06 06:54:01 tmacam Exp $
 */

#include <ext/hash_map>

#include "LogParser.h"


typedef __gnu_cxx::hash_map<std::string,unsigned long int> fileid_int_hash_t;


namespace __gnu_cxx
{
        template<> struct hash< std::string >
        {
                size_t operator()( const std::string& x ) const
                {
                        return hash< const char* >()( x.c_str() );
                }
        };
};

class MaxOffsetParser : public LogParser{
protected:
	virtual void onSendingPart(  std::string& hash,
			offset_t& offset);
	virtual void onSendingCompressed(  std::string& hash,  
			offset_t& offset);
public:
	fileid_int_hash_t h;
	MaxOffsetParser(istream& file, int n_hashes=100) : LogParser(file),h(n_hashes){}
};

#endif /* __MAX_OFFSET_PARSER_H__*/
