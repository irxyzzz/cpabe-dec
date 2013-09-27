#ifndef DECRYPT_H_
#define DECRYPT_H_
#include "InternalNode.h"
#include "Node.h"

typedef struct{
  int index;
  element_t value;
} Tuple;
bool decrypt(element_t& m, CipherText& ct, Key& key);
bool computeNode(element_t& v, Node* node, CipherText& ct, Key& key);
int computeSons(Tuple* t,InternalNode* node,  CipherText& ct, Key& key);
void langrange(element_t& v, Tuple* t, InternalNode* node, CipherText& ct);
#endif
