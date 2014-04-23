#ifndef MBDNSMESSAGE_H
#define MBDNSMESSAGE_H

#include "types.h"



typedef struct{
    DNSshort ID;
    DNSshort FLAGS; //|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    DNSshort QDCOUNT;
    DNSshort ANCOUNT;
    DNSshort NSCOUNT;
    DNSshort ARCOUNT;
	
}DNSHeader;

typedef struct{
    DNSint COUNT;
    DNSchar **NAMES;
    DNSint QTYPE;
    DNSint QCLASS;
}DNSQuestion;

typedef struct{
    DNSshort QTYPE;
    DNSshort QCLASS;
}DNSQuestion_Values;

typedef struct{
    DNSint COUNT;
    DNSchar **NAMES;
    DNSushort TYPE;
    DNSushort CLASS;
    DNSuint TTL;
    DNSint RDLENGTH;
    void *RDATA;
}DNSRR;

typedef struct{
    DNSshort TYPE;
    DNSshort CLASS;
    DNSuint TTL;
    DNSshort RDLENGTH;
}DNSRR_Values;

typedef struct{
    DNSint Length;
    DNSbyte *Data;
}DNSRowMessage;
typedef struct{
    DNSint id;
    DNSushort qr;
    DNSushort opcode;
    DNSushort aa;
    DNSushort tc;
    DNSushort rd;
    DNSushort ra;
    DNSushort rcode;
    DNSint qdcount;
    DNSint ancount;
    DNSint nscount;
    DNSint arcount;
    DNSQuestion **Question;
    DNSRR **Answer;
    DNSRR **Authority;
    DNSRR **Additional;
}DNSMessage;
typedef struct{
    DNSbyte data[512]; //maximum size
    DNSint length;
}DNSEncodedMessage;
typedef struct{
    DNSchar *label;
    DNSshort pos;
}EncodedLabel;
typedef struct{
    EncodedLabel *labels;
    DNSint count;
}EncodedLabelsArray;


#endif //MBDNSMESSAGE_H
