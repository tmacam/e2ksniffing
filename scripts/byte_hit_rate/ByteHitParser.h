#ifndef __BYTE_HIT_PARSER_H__
#define __BYTE_HIT_PARSER_H__
/**@file ByteHitParser.h
 * @brief Calcula o Byte Hit Rate
 * @author Tiago Alves Macambira <tmacam () dcc ufmg br>
 * @version $Id: ByteHitParser.h,v 1.1 2004-05-06 06:54:00 tmacam Exp $
 */

#include <ext/hash_map>
#include <vector>

#include "LogParser.h"

typedef unsigned int offset_count_t;
typedef std::vector<offset_count_t> frag_hit_list_t;
typedef __gnu_cxx::hash_map<std::string, frag_hit_list_t > fileid_frags_hash_t;


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

void updateByteHits(frag_hit_list_t& fragments, offset_count_t& start,
		offset_count_t& length, unsigned int PARTSIZE); 

class ByteHitParser : public LogParser{
protected:
	virtual void onSendingPart(  std::string& hash,
			offset_t& offset);
	virtual void onSendingCompressed(  std::string& hash,  
			offset_t& offset);
	unsigned int PARTSIZE;
public:
	fileid_frags_hash_t& hit_hash;
	
	ByteHitParser(istream& file, fileid_frags_hash_t& hit_hash,
		unsigned int frag_len) : LogParser(file),
		hit_hash(hit_hash),PARTSIZE(frag_len){}

};

#endif /* __BYTE_HIT_PARSER_H__ */
