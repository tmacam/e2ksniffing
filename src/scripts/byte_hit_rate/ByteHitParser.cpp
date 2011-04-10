/**@file ByteHitParser.cpp
 * @brief ByteHitParser - Implementação
 * @author Tiago Alves Macambira <tmacam () dcc ufmg br>
 * @version $Id: ByteHitParser.cpp,v 1.1 2004-05-06 06:54:00 tmacam Exp $
 */

#include "ByteHitParser.h"



void ByteHitParser::onSendingPart( std::string& hash, offset_t& offset)
{
	offset_count_t start = offset.first;
	offset_count_t length = offset.second - start;
	updateByteHits( hit_hash[hash], start, length , PARTSIZE);

}

void ByteHitParser::onSendingCompressed( std::string& hash, offset_t& offset )
{
	offset_count_t start = offset.first;
	offset_count_t length = offset.second ;
	updateByteHits( hit_hash[hash], start, length ,PARTSIZE);
	
}

void updateByteHits(frag_hit_list_t& fragments,
	offset_count_t& start, offset_count_t& length, unsigned int PARTSIZE)
{
	/* Lembrando: o primeiro fragmento,f[0], inicia em 0 e vai ate 
	 * frag_len - 1.
	 */
	offset_count_t fragmento_inicial, fragmento_final, bytes;

	fragmento_inicial = int( start/PARTSIZE );
	fragmento_final = int( (start + length - 1)/PARTSIZE );

	// Sanity Check
	if (length == 0) {
		return;
	}
	// Esse pedido cruza fragmentos?
	if ( fragmento_final == fragmento_inicial ){
		bytes = length;
		fragments[fragmento_inicial] += bytes;
	} else {
		// Esse pedido cruza vários fragmentos
		// Contabiliza o primeiro fragmento
		bytes = (PARTSIZE * (fragmento_inicial+1)) - start;
		fragments[fragmento_inicial] += bytes;
		// contabiliza o restante, se existir
		for (int i = fragmento_inicial + 1; i < fragmento_final; ++i){
			fragments[i] += PARTSIZE;
		}
		// e o final
		bytes = (start+length) - (PARTSIZE * fragmento_final);
		fragments[fragmento_final] += bytes;
	}
	
}
