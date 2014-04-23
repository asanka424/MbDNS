#include "mbdns.h"



DNSError decodeDNSMessage(DNSMessage *message, DNSbyte *rowdata, DNSint msgLength)
{
    //check the header first
    DNSHeader *header = (DNSHeader *)rowdata;
    message->id = ntohs((DNSint)header->ID);
    message->qr = (header->FLAGS & QR) >> QR_SHIFT;
    message->opcode = (header->FLAGS & OPCODE )>> OPCODE_SHIFT;
    message->aa = (header->FLAGS & AA) >> AA_SHIFT;
    message->tc = (header->FLAGS & TC) >> TC_SHIFT;
    message->rd = (header->FLAGS & RD) >> RD_SHIFT;
    message->ra = (header->FLAGS & RA) >> RA_SHIFT;
    message->rcode = (header->FLAGS & RCODE);
    message->qdcount = ntohs(header->QDCOUNT);
    message->ancount = ntohs(header->ANCOUNT);
    message->nscount = ntohs(header->NSCOUNT);
    message->arcount = ntohs(header->ARCOUNT);    
    //message->AA = (header->FLAGS & AA ) >> AA_SHIFT;
    DNSint tagPos = 0;

    message->Question = NULL;
    message->Answer = NULL;
    message->Authority = NULL;
    message->Additional = NULL;

    //decode questions
    int qCount = ntohs((DNSint)header->QDCOUNT);
    for (int i=0; i<qCount; i++)
    {
        message->Question = (DNSQuestion **)realloc(message->Question,(i+1) * sizeof(DNSQuestion *));
        message->Question[i] = (DNSQuestion *)calloc(1,sizeof(DNSQuestion));
        DNSQuestion *question = message->Question[i];
        question->NAMES = NULL;
        tagPos = sizeof(DNSHeader);
        DNSint nameCount = 0;
        tagPos = extractNameLabels(rowdata,tagPos,&nameCount,&(question->NAMES));
        question->COUNT = nameCount;
        DNSQuestion_Values *vals = (DNSQuestion_Values *)&rowdata[tagPos];
        question->QTYPE = ntohs(vals->QTYPE);
        question->QCLASS = ntohs(vals->QCLASS);
        tagPos += 4;
    }

    //check end of message
    if (tagPos > msgLength)
        return DNS_NONE;

    //decode answers
    int anCount = ntohs((DNSint)header->ANCOUNT);
    for (int i=0; i<anCount; i++)
    {
        message->Answer = (DNSRR **)realloc(message->Answer,(i+1) * sizeof(DNSRR *));
        tagPos = decodeRR(rowdata,tagPos,&(message->Answer[i]));
    }
    //check end of message;
    if (tagPos > msgLength)
        return DNS_NONE;

    //decode authorities
    int auCount = ntohs((DNSint)header->NSCOUNT);
    for (int i=0; i<auCount; i++)
    {
        message->Authority = (DNSRR **)realloc(message->Authority,(i+1) * sizeof(DNSRR *));
        tagPos = decodeRR(rowdata,tagPos,&(message->Authority[i]));
    }
    //check end of message;
    if (tagPos > msgLength)
        return DNS_NONE;

    //decode additional records
    int arCount = ntohs((DNSint)header->ARCOUNT);
    for (int i=0; i<arCount; i++)
    {
        message->Additional = (DNSRR **)realloc(message->Additional,(i+1) * sizeof(DNSRR *));
        tagPos = decodeRR(rowdata,tagPos,&(message->Additional[i]));
    }

    return DNS_NONE;

}
DNSint decodeRR(DNSbyte *rowdata, DNSint tagPos, DNSRR **rrData)
{
    *rrData = (DNSRR *)calloc(1,sizeof(DNSRR));
    (*rrData)->NAMES = NULL;
    DNSint nameCount = 0;
    tagPos = extractNameLabels(rowdata,tagPos,&nameCount,&((*rrData)->NAMES));
    (*rrData)->COUNT = nameCount;
    DNSRR_Values *vals = (DNSRR_Values *)&rowdata[tagPos];
    (*rrData)->TYPE = ntohs(vals->TYPE);
    (*rrData)->CLASS = ntohs(vals->CLASS);
    (*rrData)->TTL = ntohl(vals->TTL);
    (*rrData)->RDLENGTH = ntohs(vals->RDLENGTH);

    tagPos += 10;
    DNSint rdLen = (*rrData)->RDLENGTH;
    decodeRDATA(rowdata,rdLen,tagPos,(*rrData)->TYPE,&(*rrData)->RDATA);
    tagPos += rdLen;
    return tagPos;
}

DNSint extractNameLabels(DNSbyte *data, DNSint startPos, DNSint *nameCount, DNSchar ***names)
{
    DNSint tagPos = startPos;
    DNSbyte tag = data[tagPos];
    DNSint length;
    //find how many names are there
    while (tag != 0x00)
    {
        if ((tag & COMPRESSED) == COMPRESSED)
        {
            //compressed
            DNSushort offset = ntohs(*((DNSushort *)&data[tagPos]));
            offset = (DNSint)(offset & (0x3FFF));
            extractNameLabels(data,(DNSint)offset,nameCount,names);
            tagPos += 2;
            return tagPos;
        }
        else
        {
            (*nameCount)++;
            DNSint nCount = *nameCount;
            (*names) = (DNSchar **)realloc(*names,nCount * sizeof(DNSchar *));
            length = tag;
            (*names)[nCount - 1] = (DNSchar *)malloc((length + 1) * sizeof(DNSchar));
            DNSchar *tmpName = (*names)[nCount - 1];
            for (int i=0; i<length; i++)
            {
                tag = data[++tagPos];
                tmpName[i] = tag;
            }
            tmpName[length] = '\0';
            tag = data[++tagPos];
        }
    }
    return ++tagPos;
}
