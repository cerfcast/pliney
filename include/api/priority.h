#ifndef _PRIORITY_H
#define _PRIORITY_H

#include <stdint.h>

#define DSCP_CS0 0          //[RFC2474]
#define DSCP_CS1 8          //[RFC2474]
#define DSCP_CS2 16         //[RFC2474]
#define DSCP_CS3 24         //[RFC2474]
#define DSCP_CS4 32         //[RFC2474]
#define DSCP_CS5 40         //[RFC2474]
#define DSCP_CS6 48         //[RFC2474]
#define DSCP_CS7 56         //[RFC2474]
#define DSCP_AF11 10        //[RFC2597]
#define DSCP_AF12 12        //[RFC2597]
#define DSCP_AF13 14        //[RFC2597]
#define DSCP_AF21 18        //[RFC2597]
#define DSCP_AF22 20        //[RFC2597]
#define DSCP_AF23 22        //[RFC2597]
#define DSCP_AF31 26        //[RFC2597]
#define DSCP_AF32 28        //[RFC2597]
#define DSCP_AF33 30        //[RFC2597]
#define DSCP_AF41 34        //[RFC2597]
#define DSCP_AF42 36        //[RFC2597]
#define DSCP_AF43 38        //[RFC2597]
#define DSCP_EF 46          //[RFC3246]
#define DSCP_VOICE_ADMIT 44 //[RFC5865]

const char *DSCP_CODEPOINT_NAMES[] = {
    "cs0",  "cs1",  "cs2",  "cs3",  "cs4",  "cs5",        "cs6",  "cs7",
    "af11", "af12", "af13", "af21", "af22", "af23",       "af31", "af32",
    "af33", "af41", "af42", "af43", "ef",   "voice-admit"};

const uint8_t DSCP_CODEPOINT_VALUES[] = {
    DSCP_CS0,  DSCP_CS1,  DSCP_CS2,  DSCP_CS3,         DSCP_CS4,  DSCP_CS5,
    DSCP_CS6,  DSCP_CS7,  DSCP_AF11, DSCP_AF12,        DSCP_AF13, DSCP_AF21,
    DSCP_AF22, DSCP_AF23, DSCP_AF31, DSCP_AF32,        DSCP_AF33, DSCP_AF41,
    DSCP_AF42, DSCP_AF43, DSCP_EF,   DSCP_VOICE_ADMIT,
};


#define ECN_ECT1 0x1
#define ECN_ECT0 0x2
#define ECN_CE 0x3
#define ECN_NOTECT 0x0

const char *ECN_NAMES[] = {"ect1", "ect0", "ce", "not-ect"};
const uint8_t ECN_VALUES[] = {ECN_ECT1, ECN_ECT0, ECN_CE, ECN_NOTECT};

#endif