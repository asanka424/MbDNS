#include "mbdns.h"

DNSError freeDNSMessage(DNSMessage *message)
{
    DNSint qCount,anCount,nsCount,arCount;
    qCount = message->qdcount;
    anCount = message->ancount;
    nsCount = message->nscount;
    arCount = message->arcount;

    //free questions
    for (DNSint i=0; i<qCount; i++)
    {
        freeDNSQuestion(message->Question[i]);
    }
    free(message->Question);
    //free answers
    for (DNSint i=0; i<anCount; i++)
    {
        freeDNSRR(message->Answer[i]);
    }
     free(message->Answer);
    //free authorities
    for (DNSint i=0; i<nsCount; i++)
    {
        freeDNSRR(message->Authority[i]);
    }
    free(message->Authority);
    //free additional records
    for (DNSint i=0; i<arCount; i++)
    {
        freeDNSRR(message->Additional[i]);
    }
    free(message->Additional);
    return DNS_NONE;
}

DNSError freeDNSQuestion(DNSQuestion *question)
{
    DNSint nameCount = question->COUNT;
    for (DNSint i=0; i< nameCount; i++)
    {
        free(question->NAMES[i]);
    }
    return DNS_NONE;
}

DNSError freeDNSRR(DNSRR *rr)
{
    DNSint nameCount = rr->COUNT;

    for (DNSint i=0; i< nameCount; i++)
    {
        free(rr->NAMES[i]);
    }
    //free(rr->RDATA);
    return DNS_NONE;
}
DNSError freeRRData(void *rrdata,DNSushort type)
{
    switch (type)
    {
        case TYPE_A:
        {
            RDATA_A *a = (RDATA_A *)rrdata;
            free(a);
            return DNS_NONE;
            break;
        }
        case TYPE_NS:
        {
            RDATA_NS *ns = (RDATA_NS *)rrdata;
            for (int i=0; i<ns->nsdname_count; i++)
                free(ns->NSDNAME[i]);
            free(ns->NSDNAME);
            free(ns);
            return DNS_NONE;
            break;
        }
        case TYPE_MD:
        {
            RDATA_MD *md = (RDATA_MD *)rrdata;
            for (int i=0; i<md->madname_count; i++)
                free(md->MADNAME[i]);
            free(md->MADNAME);
            free(md);
            return DNS_NONE;
            break;
        }
        case TYPE_MF:
        {
            RDATA_MF *mf = (RDATA_MF *)rrdata;
            for (int i=0; i<mf->madname_count; i++)
                free(mf->MADNAME[i]);
            free(mf->MADNAME);
            free(mf);
            break;
        }
        case TYPE_CNAME:
        {
            RDATA_CNAME *cname = (RDATA_CNAME *)rrdata;
            for (int i=0; i<cname->cname_count; i++)
                free(cname->CNAME[i]);
            free(cname->CNAME);
            free(cname);
            return DNS_NONE;
            break;
        }
        case TYPE_SOA:
        {
            RDATA_SOA *soa = (RDATA_SOA *)rrdata;
            for (int i=0; i<soa->mname_count; i++)
                free(soa->MNAME[i]);
            free(soa->MNAME);
            for (int i=0; i<soa->rname_count; i++)
                free(soa->RNAME[i]);
            free(soa->RNAME);
            free(soa);
            break;
        }
        case TYPE_MB:
        {
            RDATA_MB *mb = (RDATA_MB *)rrdata;
            for (int i=0; i<mb->madname_count; i++)
                free(mb->MADNAME[i]);
            free(mb->MADNAME);
            free(mb);
            break;
        }
        case TYPE_MG:
        {
            RDATA_MG *mg = (RDATA_MG *)rrdata;
            for (int i=0; i<mg->mgmname_count; i++)
                free(mg->MGMNAME[i]);
            free(mg->MGMNAME);
            free(mg);
            break;
        }
        case TYPE_MR:
        {
            RDATA_MR *mr = (RDATA_MR *)rrdata;
            for (int i=0; i<mr->newname_count; i++)
                free(mr->NEWNAME[i]);
            free(mr->NEWNAME);
            free(mr);
            return DNS_NONE;
            break;
        }
        case TYPE_NULL:
        {
            RDATA_NULL *nul = (RDATA_NULL *)rrdata;
            free(nul);
            break;
        }
        case TYPE_WKS:
        {
            RDATA_WKS *wks = (RDATA_WKS *)rrdata;
            free(wks);
            break;
        }
        case TYPE_PTR:
        {
            RDATA_PTR *ptr = (RDATA_PTR *)rrdata;
            for (int i=0; i<ptr->ptrdname_count; i++)
                free(ptr->PTRDNAME[i]);
            free(ptr->PTRDNAME);
            free(ptr);
            return DNS_NONE;
            break;
        }
        case TYPE_HINFO:
        {
            RDATA_HINFO *hinfo = (RDATA_HINFO *)rrdata;
            free(hinfo->CPU);
            free(hinfo->OS);
            free(hinfo);
            return DNS_NONE;
            break;
        }
        case TYPE_MINFO:
        {
            RDATA_MINFO *minfo = (RDATA_MINFO *)rrdata;
            free(minfo);
            break;
        }
        case TYPE_MX:
        {
            RDATA_MX *mx = (RDATA_MX *)rrdata;
            for (int i=0; i<mx->exchange_count; i++)
                free(mx->EXCHANGE[i]);
            free(mx->EXCHANGE);
            free(mx);
            return DNS_NONE;
            break;
        }
        case TYPE_TXT:
        {
            RDATA_TXT *txt = (RDATA_TXT *)rrdata;
            free(txt);
            break;
        }
        case TYPE_AAAA:
        {
            RDATA_AAAA *aaaa = (RDATA_AAAA *)rrdata;
            free(aaaa);
            return DNS_NONE;
        }
        default:
        {
            break;
        }

    }
    return DNS_NONE;
}
