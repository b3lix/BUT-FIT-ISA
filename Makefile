CC=g++
TAGS=-fpermissive

secret: secret.cpp
	${CC} ${TAGS} secret.cpp -o secret -lcrypto -lpcap