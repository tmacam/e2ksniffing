#ifndef WRITERSPOOL_H
#define WRITERSPOOL_H

#include "FragmentedFileWriter.h"
#include <string>
#include <ext/hash_map>

/* GNU's hash_map needs this declaration - go figure why */
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



/**@Brief This class manages a pool of FragmentedFileWriters
 * 
 * FragmentedFileWriters have no locking mechanisms: two instances can be
 * created to manage one single fileID at the same time, indepedently managing
 * the written intervals. The last one to be destroied will store only a partial
 * interval data - what is not what one would expect. To prevent this, assuring
 * that there will be only one FileWriter per fileID, one should use a
 * WritersPool.
 * 
 * Besides keeping references to previously created FileWrites, it provides
 * reference counting of them. Thus, unused FileWrites will be destroied without
 * user interaction.
 * 
 * @warning This class should be used as a singleton. I will not write code to
 * prevent multiples instances of this class but one must keep in mind that
 * having more then one WritersPool around completely voids its purpose.
 * 
 */
class WritersPool{

protected:
	typedef std::pair<FragmentedFileWriter*,int> writer_ref_t;
	typedef __gnu_cxx::hash_map<std::string, writer_ref_t > writers_hash_t;
	
	writers_hash_t pool;
	std::string base_path;
public:
	/**@brief The constructor, damn it!
	 * 
	 * @param path The base path/directory where all the writers will
	 * 		their files into.
	 */
	WritersPool(const std::string& path = "./") : base_path(path) { } 
	virtual ~WritersPool();
	
	static const writer_ref_t NULL_REF;
	
	/**@brief Get a instance of a fragmenteFileWriter responsable for
	 * reassembling (a file with) a given fileId. Increments the FFW
	 * ref-count.
	 * 
	 * @return  Returns a intance of a previously created
	 * FragmentedFileWriter or newly created a new one. In case of
	 * rerror NULL (0) is returned.
	 */
	FragmentedFileWriter* getWriter(const std::string& file_id);
	
	void releaseWriter(const std::string& file_id);

};

#endif // WRITERSPOOL_H
