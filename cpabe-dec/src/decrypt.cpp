#include <pbc.h>
#include <string.h>
#include <openssl/sha.h>

#include "CipherText.h"
#include "PubParam.h"
#include "Policy.h"
#include "Node.h"
#include "Leaf.h"
#include "InternalNode.h"
#include "Key.h"
#include "decrypt.h"
#include "Utility.h"

bool decrypt(element_t& m, CipherText& ct, Key& key) {
	element_t root_value;
	element_init_GT(root_value, *(ct.p));
	Node* root = ct.getPolicy()->getRoot();
	if (!computeNode(root_value, root, ct, key)) {
		return false;
	}

	printf("decrypt:computeNode at root is ok");

	pairing_apply(m, ct.c0, key.d0, *(ct.p));  //compute e(C0, D0)
	element_mul(m, m, root_value);           //compute e(C0, D0)*e(g,g)^rs
	element_div(m, ct.c1, m);                //compute C1/(e(C0, D0)*e(g,g)^rs)
	return true;
}

void langrange(element_t& v, Tuple* t, InternalNode* node, CipherText& ct) {
	int i = 0;
	int j = 0;
	element_t numerator;
	element_t denominator;
	element_t delta;
	element_init_Zr(numerator, *(ct.p));
	element_init_Zr(denominator, *(ct.p));
	element_init_Zr(delta, *(ct.p));
	element_set1(v);
	int k = node->getK();
	for (i = 0; i < k; i++) {
		element_set1(delta);
		for (j = 0; j < k; j++) {
			if (i != j) {
				element_set_si(numerator, 0 - t[j].index);
				element_set_si(denominator, t[i].index - t[j].index);
				element_div(numerator, numerator, denominator);
				element_mul(delta, delta, numerator);
			}
		}
		element_pow_zn(t[i].value, t[i].value, delta);
		element_mul(v, v, t[i].value);
	}
}

int computeSons(Tuple* t, InternalNode* node, CipherText& ct, Key& key) {
//t to store the valid index and the value
	int valid_num = 0;
	int j = 0;
	element_t value;
	element_init_GT(value, *(ct.p));
	Node** sons = node->getSons();
	int num = node->getNum();
	for (j = 0; j < num; j++) {
		if (computeNode(value, sons[j], ct, key)) {
			t[valid_num].index = j + 1;
			element_init_GT(t[valid_num].value, *(ct.p));
			element_set(t[valid_num].value, value);
			valid_num++;
		}
//    printf("compute one leaf\n");
	}
	return valid_num;
}

bool computeNode(element_t& v, Node* node, CipherText& ct, Key& key) {
	if (node->getType() == LEAF) {
		Leaf* leaf = (Leaf*) node;
		unsigned int pos;
		printf("key.num:%d\n", key.num);
		//find corresponding hash value in key
		for (pos = 1; pos <= key.num; pos++) {
			if (leaf->valueEquals(key.attrs[pos])) {
				break;
			}
		}
		printf("the pos in key is %d\n", pos);
		if (pos == (key.num + 1)) { // this attribute doesn't exist in the key.
			return false;
		}

		element_t temp;
		element_init_GT(temp, *(ct.p));
		pairing_apply(temp, leaf->cji, key.dj[pos], *(ct.p));
		element_set(v, temp);
		printf("e(cji, dj) ok\n");
		element_printf("v:%B\n", v);
		return true;
	} else if (node->getType() == INTERNAL_NODE) {
		InternalNode* internalNode = (InternalNode*) node;
		int num = internalNode->getNum(); //number of its sons
		Tuple* t = (Tuple*) malloc(sizeof(Tuple) * num);
		int valid_num = computeSons(t, internalNode, ct, key);
		printf("valid_k: %d,\tk: %d", valid_num, internalNode->getK());
		printf("computeSons ok\n");
		if (valid_num >= internalNode->getK()) {
			langrange(v, t, internalNode, ct);
			free(t);
			return true;
		} else {
			free(t);
			return false;
		}
	} else {
	}

	return false;
}

/**
 *@param args [ct file, key file]
 */

int main(int argc, char* args[]) {
	if (argc < 4) {
		printf("please input basepath, ct file path and key path!\n");
		return -1;
	}
	const char* base_path = args[1];
	const char* ct_path = args[2];
	const char* key_path = args[3];

	//set param_path
	int base_path_len = strlen(base_path);
	const char* param_file = "/param/a1.param";
	int param_path_len = base_path_len + strlen(param_file) + 1;
	char* param_path = (char*) malloc(param_path_len);
	strncpy(param_path, base_path, base_path_len);
	strncpy(param_path + base_path_len, param_file, strlen(param_file));
	param_path[param_path_len - 1] = '\0';

	//set aes_key_path
	const char* aes_key_file = "/tmp/aesKey.dat";
	int aes_key_len = base_path_len + strlen(aes_key_file) + 1;
	char* aes_key_path = (char*) malloc(sizeof(char) * (aes_key_len));
	strncpy(aes_key_path, base_path, base_path_len);
	strncpy(aes_key_path + base_path_len, aes_key_file, strlen(aes_key_file));
	aes_key_path[aes_key_len - 1] = '\0';
	printf("aes key path is %s\n", aes_key_path);

	//read ct file
	printf("start to read ct file ok\n");
	ByteString bytes;
	FILE* f = fopen(ct_path, "rb");
	int len = 0;
	char buf[1024];
	while (feof(f)==0) {
		len = fread(buf, 1, 1024, f);
		bytes.append((unsigned char*) buf, len);
	}
	len = bytes.getLength();
	printf("%d\n", len);
	unsigned char* ct_data = (unsigned char*) malloc(
			sizeof(unsigned char) * len);
	bytes.toBytes(ct_data);
	printf("read ct file ok\n");

	//read pairing parameters
	pairing_t p;
	Utility::init_pairing(p, param_path);

	printf("init pairing ok\n");

	CipherText ct(ct_data, &p); //read c0 and c1,reconstruct policy
	printf("init ciphertext ok\n");

	//initial Key
	int key_size = Utility::size(key_path);
	printf("size of key is %d\n", key_size);
	unsigned char* key_buf = (unsigned char*) malloc(
			sizeof(unsigned char) * key_size);
	Utility::load(key_path, key_buf, key_size);
	Key key(key_buf, p);
	printf("init key ok\n");

	element_t m1;
	element_init_GT(m1, p);
	bool ok = decrypt(m1, ct, key);
	if (!ok) {
		printf("CP-ABE decrypt fail!\n");
		return -2;
	}
	printf("CP-ABE decrypt success!\n");

	int m_len = element_length_in_bytes(m1);
	unsigned char* m_buf = (unsigned char*) malloc(
			sizeof(unsigned char*) * len);
	element_to_bytes(m_buf, m1);
	f = fopen(aes_key_path, "w");
	fwrite(m_buf, 1, m_len, f);
	fclose(f);
	free(m_buf);
	return 0;
}
