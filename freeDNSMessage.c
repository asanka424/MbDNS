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
    free(rr->RDATA);
    return DNS_NONE;
}
