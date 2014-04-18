#ifndef MBDNSMESSAGE_H
#define MBDNSMESSAGE_H

#include "types.h"
#include "DNSMessage_RDATA.h"


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
    DNSbyte *RDATA;
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
    DNSint qr;
    DNSint opcode;
    DNSbyte aa;
    DNSbyte tc;
    DNSbyte rd;
    DNSbyte ra;
    DNSint rcode;
    DNSint qdcount;
    DNSint ancount;
    DNSint nscount;
    DNSint arcount;
    DNSQuestion **Question;
    DNSRR **Answer;
    DNSRR **Authority;
    DNSRR **Additional;
}DNSMessage;


#endif //MBDNSMESSAGE_H
