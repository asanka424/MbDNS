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
#include "DNSMessage_RDATA.h"

#ifdef __cplusplus
extern "C" DNSError decodeDNSMessage(DNSMessage *message, DNSbyte *rowdata, DNSint length);
extern "C" DNSError freeDNSMessage(DNSMessage *message);
#endif


DNSint extractNameLabels(DNSbyte *data, DNSint startPos, DNSint *nameCount, DNSchar ***names);
DNSError extractNames(DNSbyte *data, DNSint *nameCount, DNSchar **names, DNSint *tagPos);
DNSint decodeRR(DNSbyte *rowdata, DNSint tagPos, DNSRR **rrData);
DNSError  decodeRDATA(DNSbyte *rowdata, DNSint len, DNSint startPos, DNSushort type, void **decoded);

DNSError freeDNSQuestion(DNSQuestion *);
DNSError freeDNSRR(DNSRR *);
DNSError freeRRData(void *, DNSushort type);


#endif // MBDNS_H
