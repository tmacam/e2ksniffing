#ifndef __INTERVAL_MAP_H__
#define __INTERVAL_MAP_H__
#include <map>
#include <iostream>

class IntervalMap
{
public:
	typedef unsigned int integral_type;
	typedef std::pair<integral_type,integral_type> integral_pair;
	typedef std::map<integral_type,integral_type>::size_type size_type;

	static const integral_pair ZERO;

	IntervalMap(){};
	//IntervalMap(const IntervalMap &m)
	//IntervalMap(InputInterator first, InputIterator last)
	void serialize(std::ostream& out);
	void serialize(std::istream& in);
	void printInterval();
	integral_pair insert(integral_type i, integral_type j);
	size_type size(){return m.size();};
	bool empty(){return m.empty();};
private:
	inline integral_type max (integral_type x, integral_type y) {
		return (x > y )? x : y ; }
protected:
	std::map<integral_type,integral_type> m;
};

#endif // __INTERVAL_MAP_H__

