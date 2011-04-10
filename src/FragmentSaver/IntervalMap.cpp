#include "IntervalMap.h"
#include <map>
#include <iostream>
#include <iterator>
#include <algorithm>


const IntervalMap::integral_pair IntervalMap::ZERO = integral_pair(0,0);


void IntervalMap::printInterval()
{
	std::map<integral_type,integral_type>::const_iterator i;
	
	std::cout << "Dumping IntervalMap contents" << std::endl;
	for(i = m.begin(); i != m.end(); ++i){
		std::cout << "[" <<  (*i).first << "," << (*i).second <<
			")" << std::endl ;
	}
}

//if (i<j) throw InvalidIntervalException
IntervalMap::integral_pair IntervalMap::insert(integral_type i, integral_type j)
{
	/* This is how we picture our iterators/intervals:
	 * 
	 *     ----------[r,s)------[i,j)-------[u,v) ------->
	 * 
	 * The only thing we know for sure about those intervals is that:
	 *
	 *  - s < u
	 *  - r <= i
	 *  - u >= i
	 *
	 *  What means that:
	 *  	- the intervals RS and UV don't intersect each other,
	 *  	- the the start of the interval IJ is between the
	 *  	  start of the intervals RS and UV and that
	 *  	- the end of the interval IJ can intersect other
	 *  	  intervals past interval UV.
	 *  
	 * BTW, the existence of invervals RS and UV is not garanteed.
	 */
	integral_type r,s;
	std::map<integral_type,integral_type>::iterator rs,ij,uv,tmp;
	std::pair< std::map<integral_type,integral_type>::iterator , bool > insert_hint;
	integral_pair result(i,j);

	insert_hint = m.insert(std::make_pair(i,j));
	ij = rs = uv =  insert_hint.first;
	--rs;
	++uv;
	//  Intervals RS and IJ's interaction (iff RS exists)
	if ( insert_hint.second ) {
		// There is no known interval starting at i.
		if ( rs != ij ) { 
			/* The interval IJ can have a intersection area with
			 * the  interval RS (IJ's predecessor). Is it tha case?
			 */
			r = (*rs).first;
			s = (*rs).second;
			if ( s >= i ){
				// There's a intersection: Let's join RS and IJ
				m.erase(ij);
				i = r;
				if ( s < j ) {
					m[i]=j;
					ij=rs;
				} else {
					// IJ contained by RJ : nothing to do
					return ZERO;
				}
			} // else... there's no intersection between RS and IJ
		} // else... there's no interval before IJ to worry about
	} else {
		/* OOPS! There exists an interval starting at i
		 * already, thus there is no need to look  the interval
		 * before IJ since it was not affected by this
		 * insertion.
		 */
		if ( (*ij).second >= j ) {
			/* The old interval starting at i contains
			 * the interval we wanna add - no need to
			 * do anythng
			 */
			return ZERO;
		} // else...  The new interval extends the old one 
	}
	
	// Interatction between intervals IJ, UV and following intervals
	while (( uv != m.end() ) && ((*uv).first <= j )){
		j = max((*uv).second, j);
		tmp = uv;
		++uv;
		m.erase(tmp);
	}
	m[i]=j;


	return result;
}


namespace std {
	ostream& operator<< ( ostream& out, const IntervalMap::integral_pair& p)
	{
		return out << p.first << "\t" << p.second;
	}

	istream& operator>> ( istream& in, IntervalMap::integral_pair& p)
	{
		return in >> p.first >> p.second;
	}
};


void IntervalMap::serialize(std::ostream& out)
{
	//FIXME: raise exceptions on IO errors
	std::ostream_iterator<integral_pair> oo(out, "\n");

	std::copy(m.begin(),m.end(),oo);
}


void IntervalMap::serialize(std::istream& in)
{
	integral_pair p;

	while( in >> p ){
                insert(p.first, p.second);
	}
}
