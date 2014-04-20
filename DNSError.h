#ifndef DNSERROR_H
#define DNSERROR_H
#include "types.h"
#include "defines.h"

typedef enum {
    DNS_NONE = 0,
    DNS_DECODE_ERROR = 1,
    DNS_ENCODE_ERROR = 2
}DNSError ;

typedef struct{
    DNSint ErrorNumber;
    DNSint ErrorFunction;
    DNSchar *ErrorString;
}DNSError_t;

#endif // DNSERROR_H
