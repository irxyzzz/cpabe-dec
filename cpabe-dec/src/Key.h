#ifndef KEY_H_
#define KEY_H_
#include "Object.h"
#include <pbc.h>
#include "PubParam.h"

class Key{
  public:
    element_t d0; //G2
    element_t* dj;  // array, the element type is G2, the length is num
    size_t num;  // number of attr
    unsigned char** tj;  // for each attribute aj in w, there is a tj. don't forget to free  memory in destructor.
    unsigned char** attrs;  // attributes. don't forget to free  memory in destructor.
  public:
    Key(char* attrs[], size_t num, element_t& alpha, element_t* t, PubParam& pub, pairing_t& p);
    Key(unsigned char* buf, pairing_t& p);
    size_t getSize();
    size_t toBytes(unsigned char* buf);
    ~Key();
};

#endif
