#ifndef MBDNS_H
#define MBDNS_H

#include "DNSMessage.h"
#include "DNSError.h"
#include "DNSMessage.h"
#include "DNSError.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#ifdef _WIN32
#include "winsock2.h"
#else
#include "netinet/in.h"
#endif

#ifdef __cplusplus
extern "C"
#endif
DNSError decodeDNSMessage(DNSMessage *message, DNSbyte *rowdata, DNSint length);
DNSError freeDNSMessage(DNSMessage *message);
DNSint extractNameLabels(DNSbyte *data, DNSint startPos, DNSint *nameCount, DNSchar ***names);
DNSError extractNames(DNSbyte *data, DNSint *nameCount, DNSchar **names, DNSint *tagPos);
DNSint decodeRR(DNSRR **rrData,DNSbyte *rowdata, DNSint tagPos);
DNSError decodeRDATA(DNSbyte *rdata, DNSushort type);


#endif // MBDNS_H
