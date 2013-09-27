cc=g++
HEADERS=-I D:/develop-env/dev/include
CFLAGS=-c $(HEADERS)
LIBSSL=D:/develop-env/dev/lib/libcrypto.a D:/develop-env/dev/lib/libssl.a
LIBPBC=D:/develop-env/dev/lib/libpbc.a
OBJFLAGS=-lpbc -lgmp

decrypt:PubParam.o  Utility.o ByteString.o Leaf.o ExLeaf.o InternalNode.o Policy.o  CipherText.o decrypt.o Key.o
	$(cc)  -o $@  PubParam.o  Utility.o  ByteString.o Leaf.o InternalNode.o ExLeaf.o  Policy.o  CipherText.o decrypt.o Key.o  $(LIBSSL) $(LIBPBC) $(OBJFLAGS)

CipherText.o: CipherText.cpp
	$(cc) $(CFLAGS) CipherText.cpp

PubParam.o:PubParam.cpp
	$(cc) $(CFLAGS) -o $@ PubParam.cpp
Leaf.o:Leaf.cpp
	$(cc) $(CFLAGS) -o $@ Leaf.cpp 
InternalNode.o: InternalNode.cpp
	$(cc) $(CFLAGS) -o $@ InternalNode.cpp
ExLeaf.o: ExLeaf.cpp
	$(cc) $(CFLAGS) -o $@ ExLeaf.cpp

Policy.o: Policy.cpp
	$(cc) $(CFLAGS) -o $@ Policy.cpp

decrypt.o: decrypt.cpp
	$(cc) $(CFLAGS) -o $@ decrypt.cpp
Key.o: Key.cpp
	$(cc) $(CFLAGS) -o $@ Key.cpp

Utility.o:Utility.cpp
	$(cc) $(CFLAGS) -o $@ Utility.cpp
ByteString.o: ByteString.cpp
	$(cc) $(CFLAGS) -o $@ ByteString.cpp
clean:
	rm *.o
