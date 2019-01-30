#include "string.hpp"

#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>
#include <stdarg.h>

template<class T>
class Buffer
{
public:
   Buffer(size_t size) { msize = size; mbuf = new T[msize]; }
   ~Buffer() { if (mbuf) delete [] mbuf; }
   T *get() { return mbuf; }
private:
   Buffer();
   size_t msize;
   T *mbuf;
};

std::string oai::cn::util::string_format( const char *format, ... )
{
   va_list args;

   va_start( args, format );
   size_t size = vsnprintf( NULL, 0, format, args ) + 1; // Extra space for '\0'
   va_end( args );

   Buffer<char> buf( size );

   va_start( args, format );
   vsnprintf( buf.get(), size, format, args  );
   va_end( args );

   return std::string( buf.get(), size - 1 ); // We don't want the '\0' inside
}

// Licence : https://creativecommons.org/licenses/by-sa/4.0/legalcode
//https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring#217605

// trim from start
std::string &oai::cn::util::ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
            std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// trim from end
std::string &oai::cn::util::rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
            std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

// trim from both ends
std::string &oai::cn::util::trim(std::string &s) {
    return oai::cn::util::ltrim(oai::cn::util::rtrim(s));
}

