
#ifndef MBTYPES_H
#define MBTYPES_H

typedef unsigned char DNSbyte;
typedef short DNSshort;
typedef unsigned short DNSushort;
typedef int DNSint;
typedef unsigned int DNSuint;
typedef char DNSchar;
typedef unsigned char DNSbool;

union{
    DNSbyte bytes[2];
    DNSshort shortVal;
}bytes2short;

#endif
