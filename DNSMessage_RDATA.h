#ifndef DNSMESSAGE_RDATA_H
#define DNSMESSAGE_RDATA_H

#include "types.h"

typedef struct{
    DNSint cname_count;
    DNSchar **CNAME;
}RDATA_CNAME;
typedef struct{
    DNSchar *CPU;
    DNSchar *OS;
}RDATA_HINFO;
typedef struct{
    DNSint madname_count;
    DNSchar **MADNAME;
}RDATA_MB;
typedef struct{
    DNSint madname_count;
    DNSchar **MADNAME;
}RDATA_MD;
typedef struct{
    DNSint madname_count;
    DNSchar **MADNAME;
}RDATA_MF;
typedef struct{
    DNSint mgmname_count;
    DNSchar **MGMNAME;
}RDATA_MG;
typedef struct{
    DNSint rmailbx_count;
    DNSchar **RMAILBX;
    DNSint emailbx_count;
    DNSchar **EMAILBX;
}RDATA_MINFO;
typedef struct{
    DNSint newname_count;
    DNSchar **NEWNAME;
}RDATA_MR;
typedef struct{
    DNSshort PREFERENCE;
    DNSint exchange_count;
    DNSchar **EXCHANGE;
}RDATA_MX;
typedef struct{
    DNSint nulldata_len;
    DNSbyte *NULLDATA;
}RDATA_NULL;
typedef struct{
    DNSint nsdname_count;
    DNSchar **NSDNAME;
}RDATA_NS;
typedef struct{
    DNSint ptrdname_count;
    DNSchar **PTRDNAME;
}RDATA_PTR;
typedef struct{
    DNSint mname_count;
    DNSchar **MNAME; //<domain-name>
    DNSint rname_count;
    DNSchar **RNAME; //<domain-name>
    DNSuint SERIAL;
    DNSuint REFRESH;
    DNSuint RETRY;
    DNSuint EXPIRE;
    DNSuint MINIMUM;
}RDATA_SOA;
typedef struct{
    DNSuint SERIAL;
    DNSuint REFRESH;
    DNSuint RETRY;
    DNSuint EXPIRE;
    DNSuint MINIMUM;
}RDATA_SOA_Values;
typedef struct{
    DNSchar *TXT_DATA;
}RDATA_TXT;
typedef struct{
    DNSbyte ADDRESS[4];
}RDATA_A;
typedef struct{
    DNSbyte ADDRESS[16];
}RDATA_AAAA;
typedef struct{
    DNSbyte ADDRESS[4];
    DNSbyte PROTOCOL;
    DNSint Length;
    DNSbyte *BIT_MAP;
}RDATA_WKS;
#endif // DNSMESSAGE_RDATA_H
