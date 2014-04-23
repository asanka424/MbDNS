#include "mbdns.h"


DNSError  decodeRDATA(DNSbyte *rawdata,DNSint len,DNSint startPos, DNSushort type, void **decoded)
{
    switch (type)
    {
        case TYPE_A:
        {
            RDATA_A *a;
            a = (RDATA_A *)malloc(sizeof(RDATA_A));
            for (int i=0; i<4; i++)
                a->ADDRESS[i] = rawdata[startPos +i];
            *decoded = (void *)a;
            return DNS_NONE;
            break;
        }
        case TYPE_NS:
        {
            RDATA_NS *ns;
            ns = (RDATA_NS *)malloc(sizeof(RDATA_NS));
            ns->nsdname_count = 0;
            ns->NSDNAME = NULL;
            extractNameLabels(rawdata,startPos,&(ns->nsdname_count),&(ns->NSDNAME));
            *decoded = (void *)ns;
            return DNS_NONE;
            break;
        }
        case TYPE_MD:
        {
            RDATA_MB *mb;
            mb = (RDATA_MB *)malloc(sizeof(RDATA_MB));
            mb->madname_count = 0;
            mb->MADNAME = NULL;
            extractNameLabels(rawdata,startPos,&(mb->madname_count),&(mb->MADNAME));
            *decoded = (void *)mb;
            return DNS_NONE;
            break;
        }
        case TYPE_MF:
        {
            RDATA_MF *mf;
            mf = (RDATA_MF *)malloc(sizeof(RDATA_MF));
            mf->madname_count = 0;
            mf->MADNAME = NULL;
            extractNameLabels(rawdata,startPos,&(mf->madname_count),&(mf->MADNAME));
            *decoded = (void *)mf;
            break;
        }
        case TYPE_CNAME:
        {
            RDATA_CNAME *cname;
            cname = (RDATA_CNAME *)malloc(sizeof(RDATA_CNAME));
            cname->cname_count = 0;
            cname->CNAME = NULL;
            extractNameLabels(rawdata,startPos,&(cname->cname_count),&(cname->CNAME));
            *decoded = (void *)cname;
            return DNS_NONE;
            break;
        }
        case TYPE_SOA:
        {
            RDATA_SOA *soa;
            soa = (RDATA_SOA *)malloc(sizeof(RDATA_SOA));
            soa->mname_count = 0;
            soa->MNAME = NULL;
            DNSint tagPos = extractNameLabels(rawdata,startPos,&(soa->mname_count),&(soa->MNAME));
            soa->rname_count = 0;
            soa->RNAME = NULL;
            tagPos = extractNameLabels(rawdata,tagPos,&(soa->rname_count),&(soa->RNAME));
            soa->SERIAL = ntohl(*(DNSuint *)&rawdata[tagPos]);
            tagPos += 4;
            soa->REFRESH = ntohl(*(DNSuint *)&rawdata[tagPos]);
            tagPos += 4;
            soa->RETRY = ntohl(*(DNSuint *)&rawdata[tagPos]);
            tagPos += 4;
            soa->EXPIRE = ntohl(*(DNSuint *)&rawdata[tagPos]);
            tagPos += 4;
            soa->MINIMUM = ntohl(*(DNSuint *)&rawdata[tagPos]);
            tagPos += 4;
            *decoded = (void *)soa;
            break;
        }
        case TYPE_MB:
        {
            RDATA_MB *mb;
            mb = (RDATA_MB *)malloc(sizeof(RDATA_MB));
            mb->madname_count = 0;
            mb->MADNAME = NULL;
            extractNameLabels(rawdata,startPos,&(mb->madname_count),&(mb->MADNAME));
            *decoded = (void *)mb;
            return DNS_NONE;
            break;
        }
        case TYPE_MG:
        {
            RDATA_MG *mg;
            mg = (RDATA_MG *)malloc(sizeof(RDATA_MG));
            mg->mgmname_count = 0;
            mg->MGMNAME = NULL;
            extractNameLabels(rawdata,startPos,&(mg->mgmname_count),&(mg->MGMNAME));
            *decoded = (void *)mg;
            return DNS_NONE;
            break;
        }
        case TYPE_MR:
        {
            RDATA_MR *mr;
            mr = (RDATA_MR *)malloc(sizeof(RDATA_MR));
            mr->newname_count = 0;
            mr->NEWNAME = NULL;
            extractNameLabels(rawdata,startPos,&(mr->newname_count),&(mr->NEWNAME));
            *decoded = (void *)mr;
            return DNS_NONE;
            break;
        }
        case TYPE_NULL:
        {
            RDATA_NULL *nul;
            nul = (RDATA_NULL *)malloc(sizeof(RDATA_NULL));
            *decoded = (void *)nul;
            break;
        }
        case TYPE_WKS:
        {
            RDATA_WKS *wks;
            wks = (RDATA_WKS *)malloc(sizeof(RDATA_WKS));
            *decoded = (void *)wks;
            break;
        }
        case TYPE_PTR:
        {
            RDATA_PTR *ptr;
            ptr = (RDATA_PTR *)malloc(sizeof(RDATA_PTR));
            ptr->ptrdname_count = 0;
            ptr->PTRDNAME = NULL;
            extractNameLabels(rawdata,startPos,&(ptr->ptrdname_count),&(ptr->PTRDNAME));
            *decoded = (void *)ptr;
            return DNS_NONE;
            break;
        }
        case TYPE_HINFO:
        {
            RDATA_HINFO *hinfo;
            hinfo = (RDATA_HINFO *)malloc(sizeof(RDATA_HINFO));
            DNSint cpulen = rawdata[startPos], oslen = rawdata[rawdata[startPos] + 1];
            hinfo->CPU = malloc((cpulen + 1)*sizeof(DNSchar));
            hinfo->OS = malloc((oslen + 1)*sizeof(DNSchar));
            for (int i=0; i<cpulen; i++)
                hinfo->CPU[i] = rawdata[startPos +i + 1];
            hinfo->CPU[cpulen] = '\0';
            for (int i=0; i<oslen; i++)
                hinfo->OS[i] = rawdata[startPos + cpulen + 2 + i];
            hinfo->OS[oslen] = '\0';
            *decoded = (void *)hinfo;
            break;
        }
        case TYPE_MINFO:
        {
            RDATA_MINFO *minfo;
            minfo = (RDATA_MINFO *)malloc(sizeof(RDATA_MINFO));
            *decoded = (void *)minfo;
            break;
        }
        case TYPE_MX:
        {
            RDATA_MX *mx;
            mx = (RDATA_MX *)malloc(sizeof(RDATA_MX));
            mx->PREFERENCE = ntohs(*(DNSshort *)rawdata);
            mx->exchange_count = 0;
            mx->EXCHANGE = NULL;
            extractNameLabels(rawdata,startPos+1,&(mx->exchange_count),&(mx->EXCHANGE));
            *decoded = (void *)mx;
            return DNS_NONE;
            break;
        }
        case TYPE_TXT:
        {
            RDATA_TXT *txt;
            txt = (RDATA_TXT *)malloc(sizeof(RDATA_TXT));
            *decoded = (void *)txt;
            break;
        }
        case TYPE_AAAA:
        {
            RDATA_AAAA *aaaa;
            aaaa = (RDATA_AAAA *)malloc(sizeof(RDATA_AAAA));
            for (int i=0; i<16; i++)
                aaaa->ADDRESS[i] = rawdata[startPos +i];
            *decoded = (void *)aaaa;
            return DNS_NONE;
        }
        default:
        {
            break;
        }

    }
    return DNS_NONE;
}
