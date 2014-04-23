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
extern "C" DNSError encodeDNSMessage(DNSMessage message,DNSEncodedMessage *encoded);
#else
DNSError decodeDNSMessage(DNSMessage *message, DNSbyte *rowdata, DNSint length);
DNSError freeDNSMessage(DNSMessage *message);
DNSError encodeDNSMessage(DNSMessage message,DNSEncodedMessage *encoded);
#endif


DNSint extractNameLabels(DNSbyte *data, DNSint startPos, DNSint *nameCount, DNSchar ***names);
DNSError extractNames(DNSbyte *data, DNSint *nameCount, DNSchar **names, DNSint *tagPos);
DNSint decodeRR(DNSbyte *rowdata, DNSint tagPos, DNSRR **rrData);
DNSError  decodeRDATA(DNSbyte *rowdata, DNSint len, DNSint startPos, DNSushort type, void **decoded);

DNSError freeDNSQuestion(DNSQuestion *);
DNSError freeDNSRR(DNSRR *);
DNSError freeRRData(void *, DNSushort type);
DNSError encodeNames(DNSchar **names, DNSint count, DNSEncodedMessage *encoded, EncodedLabelsArray *labelDB);
DNSshort queryNamePointer(EncodedLabelsArray *labelDB,DNSchar *label,DNSshort pos);
DNSError encodeRR(DNSRR *rr, DNSEncodedMessage *encoded, EncodedLabelsArray *labelDB);
DNSError encodeRData(void *rdata, DNSint type, DNSEncodedMessage *encoded, EncodedLabelsArray *labelDB);

#endif // MBDNS_H
