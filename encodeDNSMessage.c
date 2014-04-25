#include "mbdns.h"

DNSError encodeDNSMessage(DNSMessage message,DNSEncodedMessage *encoded)
{
    //maximum size for dns message is 512 bytes.
    encoded->length = 0;
    DNSHeader *header = (DNSHeader *)&encoded->data[encoded->length];
    header->ID = (DNSshort)htons(message.id);
    DNSushort flags = 0;
    flags = flags | (message.qr << QR_SHIFT); //qr
    flags = flags | (message.opcode << OPCODE_SHIFT); //opcode
    flags = flags | (message.aa << AA_SHIFT); //aa
    flags = flags | (message.tc << TC_SHIFT); //tc
    flags = flags | (message.rd << RD_SHIFT); //rd
    flags = flags | (message.ra << RA_SHIFT); //ra
    flags = flags | (message.rcode); //rcode
    header->FLAGS = (flags);
    header->QDCOUNT = (DNSshort)htons(message.qdcount);
    header->ANCOUNT = (DNSshort)htons(message.ancount);
    header->NSCOUNT = (DNSshort)htons(message.nscount);
    header->ARCOUNT = (DNSshort)htons(message.arcount);

    encoded->length += 12;
    EncodedLabelsArray labelDB;
    labelDB.count = 0;
    labelDB.labels = NULL;
    //encoding questions
    for (int i=0; i<message.qdcount; i++)
    {
        DNSQuestion *question = message.Question[i];
        encodeNames(question->NAMES,question->COUNT,encoded,&labelDB);
        DNSQuestion_Values *qvals = (DNSQuestion_Values *)&encoded->data[encoded->length];
        qvals->QTYPE = (DNSshort)htons(question->QTYPE);
        qvals->QCLASS = (DNSshort)htons(question->QCLASS);
        encoded->length += 4;
    }
    //encode answers
    for (int i=0; i<message.ancount; i++)
    {
        DNSRR *rr = message.Answer[i];
        encodeRR(rr,encoded,&labelDB);
    }
    //encode authorities
    for (int i=0; i<message.nscount; i++)
    {
        DNSRR *rr = message.Authority[i];
        encodeRR(rr,encoded,&labelDB);
    }
    //encode additional
    for (int i=0; i<message.arcount; i++)
    {
        DNSRR *rr = message.Additional[i];
        encodeRR(rr,encoded,&labelDB);
    }
    //free labelDB
    for (int i=0; i<labelDB.count; i++)
    {
        EncodedLabel enLabel = labelDB.labels[i];
        free(enLabel.label);
    }
    free(labelDB.labels);
    return DNS_NONE;
}
DNSError encodeRR(DNSRR *rr, DNSEncodedMessage *encoded, EncodedLabelsArray *labelDB)
{
    encodeNames(rr->NAMES,rr->COUNT,encoded,labelDB);
    DNSRR_Values *rrVals = (DNSRR_Values *)&encoded->data[encoded->length];
    rrVals->TYPE = htons(rr->TYPE);
    rrVals->CLASS = htons(rr->CLASS);
    rrVals->TTL = htonl(rr->TTL);
    rrVals->RDLENGTH = htons(rr->RDLENGTH);
    encoded->length += 10;
    encodeRData(rr->RDATA,rr->TYPE,encoded,labelDB);
    return DNS_NONE;
}

DNSError encodeNames(DNSchar **names, DNSint count, DNSEncodedMessage *encoded, EncodedLabelsArray *labelDB)
{
    //prepare encoded name
    DNSchar **tmpNames = NULL;
    tmpNames = (DNSchar **)malloc(count*sizeof(DNSchar *));
    for (int i=0; i<count; i++)
    {
        tmpNames[i] = NULL;
        DNSint totalLen = 0;
        for (int j=i; j<count; j++)
        {
            DNSint nameLen = strlen(names[j]);
            DNSint offset = totalLen;
            totalLen += nameLen;
            tmpNames[i] = (DNSchar *)realloc(tmpNames[i], totalLen*sizeof(DNSchar));
            for (int k=0; k<nameLen; k++)
            {
                tmpNames[i][offset + k] = names[j][k];
            }
        }
        tmpNames[i] = (DNSchar *)realloc(tmpNames[i], (totalLen + 1)*sizeof(DNSchar));
        tmpNames[i][totalLen] = '\0';
    }
    DNSbool pointerFound = 0;
    for (int i=0; i<count; i++)
    {
        DNSchar *tmpName = tmpNames[i];
        DNSint nameLen = strlen(names[i]);
        DNSshort ptr = queryNamePointer(labelDB,tmpName,encoded->length);
        if (ptr == 0)
        {
            encoded->data[(encoded->length)++] = (DNSbyte)nameLen;
            for (int j=0; j<nameLen; j++)
                encoded->data[(encoded->length)++] = names[i][j];
        }
        else
        {
            ptr = (0xC000 | ptr);
            DNSushort *p_msgPtr = (DNSushort *)&encoded->data[encoded->length];
            *p_msgPtr = htons(ptr);
            encoded->length += 2;
            pointerFound = 1;
            break;
        }
    }
    if (!pointerFound)
        encoded->data[(encoded->length)++] = 0x00; //root
    //free momory;
    for (int i=0; i<count; i++)
    {
        free(tmpNames[i]);
    }
    free(tmpNames);
    return DNS_NONE;
}

DNSshort queryNamePointer(EncodedLabelsArray *labelDB, DNSchar *label, DNSshort pos)
{
    DNSshort retVal = 0;
    DNSbool entryFound = 0;
    for (int i=0; i<labelDB->count; i++)
    {
        EncodedLabel label1 = labelDB->labels[i];
        if (0 == strcmp(label1.label,label))
        {
            entryFound = 1;
            retVal = label1.pos;
            break;
        }
    }
    if (!entryFound)
    {
        labelDB->labels = (EncodedLabel *)realloc(labelDB->labels,((labelDB->count) + 1) * sizeof(EncodedLabel));
        labelDB->labels[(labelDB->count)].label = (DNSchar *)malloc((strlen(label) + 1) * sizeof(DNSchar));
        strcpy(labelDB->labels[labelDB->count].label,label);
        labelDB->labels[(labelDB->count)++].pos = pos;
    }
    return retVal;
}
