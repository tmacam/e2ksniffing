/**@file MaxOffsetParser.cpp
 * @brief Procura o maior offset mencionado em uma troca de arquivos edonkey
 * @author Tiago Alves Macambira <tmacam () dcc ufmg br>
 * @version $Id: MaxOffsetParser.cpp,v 1.1 2004-05-06 06:54:01 tmacam Exp $
 */

#include "LogParser.h"
#include "MaxOffsetParser.h"



void MaxOffsetParser::onSendingPart( std::string& hash,
		offset_t& offset)
{
	unsigned int sum = offset.first + offset.second;
	if ( h.find(hash) == h.end() ||  h[hash] < sum  ){
		h[hash] = sum;
	};
}

void MaxOffsetParser::onSendingCompressed( std::string& hash, 
		offset_t& offset )
{
	unsigned int sum = offset.first + offset.second;
	if ( h.find(hash) == h.end() ||  h[hash] < sum  ){
		h[hash] = sum;
	};
}


