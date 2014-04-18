#ifndef MBDEFINES_H
#define MBDEFINES_H

//header fields
#define QR 0x8000
#define OPCODE 0x7800
#define AA 0x0400
#define TC 0x0200
#define RD 0x0100
#define RA 0x0080 
#define RCODE 0x000F

#define QR_SHIFT 15
#define OPCODE_SHIFT 11
#define AA_SHIFT 10
#define TC_SHIFT 9
#define RD_SHIFT 8
#define RA_SHIFT 7

#define QR_QUERY 0
#define QR_RESPONSE 1
#define OPCODE_QUERY 0
#define OPCODE_IQUERY 1
#define OPCODE_STATUS 2

#define RCODE_NOERROR 0
#define RCODE_FORMATERROR 1
#define RCODE_SEVERFAILURE 2
#define RCODE_NAMEERROR 3
#define RCODE_NOTIMPLEMENTED 4
#define RCODE_REFUSED 5

#define TYPE_A               1 //a host address
#define TYPE_NS              2 //an authoritative name server
#define TYPE_MD              3 //a mail destination (Obsolete - use MX)
#define TYPE_MF              4 //a mail forwarder (Obsolete - use MX)
#define TYPE_CNAME           5 //the canonical name for an alias
#define TYPE_SOA             6 //marks the start of a zone of authority
#define TYPE_MB              7 //a mailbox domain name (EXPERIMENTAL)
#define TYPE_MG              8 //a mail group member (EXPERIMENTAL)
#define TYPE_MR              9 //a mail rename domain name (EXPERIMENTAL)
#define TYPE_NULL            10 //a null RR (EXPERIMENTAL)
#define TYPE_WKS             11 //a well known service description
#define TYPE_PTR             12 //a domain name pointer
#define TYPE_HINFO           13 //host information
#define TYPE_MINFO           14 //mailbox or mail list information
#define TYPE_MX              15 //mail exchange
#define TYPE_TXT             16 //text strings

#define QTYPE_AXFR           252 //A request for a transfer of an entire zone
#define QTYPE_MAILB          253 //A request for mailbox-related records (MB, MG or MR)
#define QTYPE_MAILA          254 //A request for mail agent RRs (Obsolete - see MX)
#define QTYPE_ALL            255 //A request for all records

#define CLASS_IN              1 //the Internet
#define CLASS_CS              2 //the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
#define CLASS_CH              3 //the CHAOS class
#define CLASS_HS              4 //Hesiod [Dyer 87]
#define QCLASS_ALL            255 any class


#define COMPRESSED 0xC0
#endif //MBDEFINES_H
