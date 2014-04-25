#include "mbdns.h"

DNSError encodeRData(void *rdata, DNSint type, DNSEncodedMessage *encoded, EncodedLabelsArray *labelDB)
{
    switch (type)
    {
        case TYPE_A:
        {
            RDATA_A *a = (RDATA_A *)rdata;
            for (int i=0; i<4; i++)
                encoded->data[(encoded->length)++] = a->ADDRESS[i];
            return DNS_NONE;
            break;
        }
        case TYPE_NS:
        {
            RDATA_NS *ns = (RDATA_NS *)rdata;
            encodeNames(ns->NSDNAME,ns->nsdname_count,encoded,labelDB);
            ns = (RDATA_NS *)malloc(sizeof(RDATA_NS));
            return DNS_NONE;
            break;
        }
        case TYPE_MD:
        {
            RDATA_MB *mb = (RDATA_MB *)rdata;
            encodeNames(mb->MADNAME,mb->madname_count,encoded,labelDB);
            return DNS_NONE;
            break;
        }
        case TYPE_MF:
        {
            RDATA_MF *mf = (RDATA_MF *)rdata;
            encodeNames(mf->MADNAME,mf->madname_count,encoded,labelDB);
            break;
        }
        case TYPE_CNAME:
        {
            RDATA_CNAME *cname = (RDATA_CNAME *)rdata;
            encodeNames(cname->CNAME,cname->cname_count,encoded,labelDB);
            return DNS_NONE;
            break;
        }
        case TYPE_SOA:
        {
            RDATA_SOA *soa = (RDATA_SOA *)rdata;
            encodeNames(soa->MNAME,soa->mname_count,encoded,labelDB);
            encodeNames(soa->RNAME,soa->rname_count,encoded,labelDB);
            RDATA_SOA_Values *soavals = (RDATA_SOA_Values *)&encoded->data[encoded->length];
            soavals->SERIAL = htonl(soa->SERIAL);
            soavals->REFRESH = htonl(soa->REFRESH);
            soavals->RETRY = htonl(soa->RETRY);
            soavals->EXPIRE = htonl(soa->EXPIRE);
            soavals->MINIMUM = htonl(soa->MINIMUM);
            encoded->length += 20;
            break;
        }
        case TYPE_MB:
        {
            RDATA_MB *mb = (RDATA_MB *)rdata;
            encodeNames(mb->MADNAME,mb->madname_count,encoded,labelDB);
            return DNS_NONE;
            break;
        }
        case TYPE_MG:
        {
            RDATA_MG *mg = (RDATA_MG *)rdata;
            encodeNames(mg->MGMNAME,mg->mgmname_count,encoded,labelDB);
            return DNS_NONE;
            break;
        }
        case TYPE_MR:
        {
            RDATA_MR *mr = (RDATA_MR *)rdata;
            encodeNames(mr->NEWNAME,mr->newname_count,encoded,labelDB);
            return DNS_NONE;
            break;
        }
        case TYPE_NULL:
        {
            RDATA_NULL *nul = (RDATA_NULL *)rdata;
            for (int i=0; i<nul->nulldata_len; i++)
            {
                encoded->data[(encoded->length)++] = nul->NULLDATA[i];
            }
            break;
        }
        case TYPE_WKS:
        {
            RDATA_WKS *wks;
            return DNS_NONE;
            break;
        }
        case TYPE_PTR:
        {
            RDATA_PTR *ptr = (RDATA_PTR *)rdata;
            encodeNames(ptr->PTRDNAME,ptr->ptrdname_count,encoded,labelDB);
            return DNS_NONE;
            break;
        }
        case TYPE_HINFO:
        {
            RDATA_HINFO *hinfo = (RDATA_HINFO *)rdata;
            DNSint cpulen = strlen(hinfo->CPU);
            DNSint oslen = strlen(hinfo->OS);
            encoded->data[(encoded->length)++] = (DNSbyte)cpulen;
            for (int i=0; i<cpulen; i++)
            {
                encoded->data[(encoded->length)++] = (DNSbyte)hinfo->CPU[i];
            }
            encoded->data[(encoded->length)++] = (DNSbyte)oslen;
            for (int i=0; i<oslen; i++)
            {
                encoded->data[(encoded->length)++] = (DNSbyte)hinfo->OS[i];
            }
            return DNS_NONE;
            break;
        }
        case TYPE_MINFO:
        {
            RDATA_MINFO *minfo;
            return DNS_NONE;
            break;
        }
        case TYPE_MX:
        {
            RDATA_MX *mx = (RDATA_MX *)rdata;
            DNSshort *p_mxptr = (DNSshort *)&encoded->data[encoded->length];
            *p_mxptr = htons(mx->PREFERENCE);
            encoded->length += 2;
            encodeNames(mx->EXCHANGE,mx->exchange_count,encoded,labelDB);
            return DNS_NONE;
            break;
        }
        case TYPE_TXT:
        {
            RDATA_TXT *txt;
            return DNS_NONE;
            break;
        }
        case TYPE_AAAA:
        {
            RDATA_AAAA *aaaa = (RDATA_AAAA *)rdata;
            for (int i=0; i<16; i++)
                encoded->data[(encoded->length)++] = aaaa->ADDRESS[i];
            return DNS_NONE;
            break;
        }
        default:
        {
            break;
        }

    }
    return DNS_NONE;
}
