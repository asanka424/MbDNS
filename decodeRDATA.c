#include "mbdns.h"

DNSError decodeRDATA(DNSbyte *rdata, DNSushort type)
{
    switch (type)
    {
    case TYPE_A:
        break;

    case TYPE_NS:
        break;
    case TYPE_MD:
        break;
    case TYPE_MF:
        break;
    case TYPE_CNAME:
        break;
    case TYPE_SOA:
        break;
    case TYPE_MB:
        break;
    case TYPE_MG:
        break;
    case TYPE_MR:
        break;
    case TYPE_NULL:
        break;
    case TYPE_WKS:
        break;
    case TYPE_PTR:
        break;
    case TYPE_HINFO:
        break;
    case TYPE_MINFO:
        break;
    case TYPE_MX:
        break;
    case TYPE_TXT:
        break;
    case QTYPE_AXFR:
        break;
    case QTYPE_MAILB:
        break;
    case QTYPE_MAILA:
        break;
    case QTYPE_ALL:
        break;
    default:
        break;

    }
    return DNS_NONE;
}
