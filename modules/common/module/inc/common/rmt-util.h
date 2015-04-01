#ifndef MODEL_COMMON_UTIL_
#define MODEL_COMMON_UTIL_

#include <cassert>
#include <string>
#include <cstdint>


namespace model_common {

  class Util {
 public:
    static uint8_t  rotr8(uint8_t val, int r)    { return (val >> r) | (val << (8-r)); }
    static uint16_t rotr16(uint16_t val, int r)  { return (val >> r) | (val << (16-r)); }
    static uint32_t rotr32(uint32_t val, int r)  { return (val >> r) | (val << (32-r)); }
    static uint8_t  rotl8(uint8_t val, int r)    { return (val << r) | (val >> (8-r)); }
    static uint16_t rotl16(uint16_t val, int r)  { return (val << r) | (val >> (16-r)); }
    static uint32_t rotl32(uint32_t val, int r)  { return (val << r) | (val >> (32-r)); }

    static bool is_little_endian();
    static int  hexchar2int(char in);
    static int  hexmakebuf(const std::string hexstr, int len, uint8_t buf[]);
    static int  hexmakebuf(const char *hexstr, int len, uint8_t buf[]);

  };
  
}

// A macro to disallow the copy constructor and operator= functions
// This should be used in the private: declarations for a class
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&);               \
  void operator=(const TypeName&)


#endif // MODEL_COMMON_UTIL_
