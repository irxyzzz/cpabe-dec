#include "Key.h"
#include "Utility.h"
#include <string.h>
#include <openssl/sha.h>

/**
*construct a <code>Key<code> from attributes
*/
Key::Key(char* attrs[], size_t num, element_t& alpha, element_t* t, PubParam& pub, pairing_t& p){
  this->num = num;

  // initial kd0
  element_t r;
  element_init_Zr(r, p);
  element_random(r);


  element_t temp;
  element_init_Zr(temp, p);
  element_sub(temp, alpha , r); //temp = alpha - r

  element_t g2_a_r;
  element_init_G2(g2_a_r, p);
  element_pow_zn(g2_a_r, pub.g2, temp);   //g2_a_r = g2^(alpha - r)

  element_init_G2(this->d0, p);
  element_set(this->d0, g2_a_r);  // d0 = g2^(alpha - r)

  //initial varibles used by bellow code
  element_t ghr;
  element_init_G2(ghr, p);

  //allocate memory for this->attrs, this->dj
  this->attrs=(unsigned char**) malloc(sizeof(unsigned char*) * (num + 1));
  this->dj = (element_t*)malloc(sizeof(element_t) * (num + 1));
      
  
  unsigned int i = 1;
  
  for(i = 1; i <= num; i++){
    this->attrs[i] = (unsigned char*)malloc(sizeof(unsigned char) * SHA_DIGEST_LENGTH);
    SHA1((unsigned char*)attrs[i], strlen(attrs[i]), this->attrs[i]);

  }
  
  //read the attribute set from file "/home/easy/work/eabe/param/attr_hash.dat"
  unsigned char buf_hash[N+1][SHA_DIGEST_LENGTH];
  const char* attr_hash_path = "../param/attr_hash.dat";
  FILE *fp = fopen(attr_hash_path, "rb");
  if (fp  == NULL){
//to do: return errno
    printf("can't open file %s for writing\n", attr_hash_path);
    exit(1);
  }
  fseek(fp, 0, SEEK_SET);

  for(i=1;i<=N;i++)
    fread(buf_hash[i],sizeof(unsigned char),SHA_DIGEST_LENGTH,fp);

  fclose(fp);
  
  //initial dj, ensure that each dj exists
  int j;
  for(i=1; i<=num; i++){
    for(j=1; j<=N; j++){
     // for(k=0;k<20;k++)
      //  printf("%d %d\n",this->attrs[i][k],buf_hash[j][k]);
      if(strncmp((const char*)this->attrs[i],(const char*)buf_hash[j],SHA_DIGEST_LENGTH) == 0){ //hash value to compare
		//printf("find attrs %d\n", j);     	
		break;
	}
    }
    
     // printf("%d\n",j);
    element_pow_zn(ghr, pub.g2, r);  //ghr = g2^r
    
    element_t invert_tj;
    element_init_Zr(invert_tj, p);
    element_invert(invert_tj, t[j]);
    element_init_G2(this->dj[i], p);
    element_pow_zn(this->dj[i], ghr, invert_tj);//dj[i]=g2^(r*tj-1)
    
  }

}


/**
* reconstruct <code>Key<code> from byte string
*/
Key::Key(unsigned char* buf, pairing_t& p){
  //get number of attributes
  this->num = Utility::str2int(buf);
 
  //allocate space for element in Key.
  this->dj = (element_t*) malloc(sizeof(element_t) * (this->num + 1));
  this->attrs = (unsigned char**) malloc(sizeof(unsigned char*) * (this->num + 1));
 
  // init d0, dj, and attrs in Key
  int pos = 4;
  element_init_G2(this->d0, p);
  pos += element_from_bytes(this->d0, buf + pos);
  unsigned int i = 0;
  for(i = 1; i <= this->num; i++){
    element_init_G2(this->dj[i], p);
    this->attrs[i] = (unsigned char*)malloc(sizeof(unsigned char) * SHA_DIGEST_LENGTH);
    pos += element_from_bytes(this->dj[i], buf + pos);
    
    memcpy((void*)this->attrs[i],(void*)(buf + pos), SHA_DIGEST_LENGTH);
    pos += SHA_DIGEST_LENGTH;
  }
}

  
  
/**
*return the size of memery to store <code>Key<code> as binary file
*/
size_t Key::getSize(){
  //'4' is the length of binary value of key->num
  return 4 + element_length_in_bytes(this->d0)
        + (element_length_in_bytes(this->dj[1]) + SHA_DIGEST_LENGTH) * this->num;
}


/**
*return the binary form  of  <code>Key<code>
*the length of buf must not less than the value returned by <code>getSize<code>
*/
size_t Key::toBytes(unsigned char* buf){
  Utility::int2str(buf, this->num);
  int pos = 4;
  pos += element_to_bytes(buf + pos, this->d0);
  unsigned int i = 1;
  for(i = 1; i <= num; i++){
    pos += element_to_bytes(buf + pos, this->dj[i]);
    memcpy((void*)(buf + pos),(void*)(this->attrs[i]), SHA_DIGEST_LENGTH);
    pos += SHA_DIGEST_LENGTH;
  }
  return pos;
}


Key::~Key(){
// TO-DO: why can't add element_free
//  element_free(d);
  unsigned int i = 0;
  for(i = 1; i <= num; i++){
//    element_free(dy[i]);
//    element_free(dyt[i]);
 
    free(attrs[i]);
  }
  free(attrs);
}
