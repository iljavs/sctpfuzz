//
//  sctpfuzz.h
//  
//
//  Created by ilja van sprundel on 8/11/17.
//
//

#ifndef sctpfuzz_h
#define sctpfuzz_h

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>

struct iphdr {
    unsigned char v_hdrlen;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
}__attribute__((packed));

struct sctp_comm_hdr {
    unsigned short sport;
    unsigned short dport;
    unsigned int tag;
    unsigned int check;
}__attribute__((packed));

struct sctp_chunk_hdr {
    unsigned char type;
    unsigned char flags;
    unsigned short len;
}__attribute__((packed));

struct sctp_init_chunk{
    unsigned int tag;
    unsigned int window_credit;
    unsigned short oob_streams;
    unsigned short iob_streams;
    unsigned int tsn;
}__attribute__((packed));

struct sctp_init_param {
    unsigned short type;
    unsigned short len;
}__attribute__((packed));

struct args {
    char *source;
    char *dest;
    unsigned int seed;
    unsigned int nr_packets;
    unsigned short sport;
    unsigned short dport;
    unsigned int max_nr_params;
    unsigned int timeout;
    int skip;
};

#define LOOP_NR 100000
#define PACKET_SIZE 1000000

#define SENTO_TIMEOUT 80

#define DEFAULT_SPORT 1337
#define DEFAULT_DPORT 2448

#define SCTP_DATA	0
#define SCTP_INIT	1
#define SCTP_INIT_ACK	2
#define SCTP_SACK	3
#define SCTP_HEARTBEAT	4
#define SCTP_HEARTBEAT_ACK	5
#define SCTP_ABORT	6
#define SCTP_SHUTDOWN	7
#define SCTP_SHUTDOWN_ACK	8
#define SCTP_ERROR	9
#define SCTP_OOKIE_ECHO	10
#define SCTP_COOKIE_ACK	11
#define SCTP_ECNE	12
#define SCTP_CWR	13
#define SCTP_SHUTDOWN_COMPLETE	14
#define SCTP_AUTH 15
#define SCTP_ASCONF_ACK 128 
#define SCTP_RECONF 130 
#define SCTP_PADDING 132
#define SCTP_FORWARD_TSN 192 


#define SCTP_PARAM_HEARTBEAT 1 
#define SCTP_PARAM_IPv4 5
#define SCTP_PARAM_IPv6 6
#define SCTP_PARAM_STATE_COOKIE 7
#define SCTP_PARAM_UNRECOGNIZED_PARAM 8
#define SCTP_PARAM_COOKIE_PRESERVATIVE 9
#define SCTP_PARAM_HOSTNAME 11
#define SCTP_PARAM_ADDRESS_TYPES 12
#define SCTP_PARAM_OUT_SSN 13
#define SCTP_PARAM_IN_SSN 14
#define SCTP_PARAM_SSN_RESET 15
#define SCTP_PARAM_RECONFIG_RESPONSE 16
#define SCTP_PARAM_ADD_OUT_REQUEST 17
#define SCTP_PARAM_ADD_IN_REQUEST 18
#define SCTP_PARAM_ECN 32768
#define SCTP_PARAM_RAND 32770
#define SCTP_PARAM_CHUNK_LIST 32771
#define SCTP_PARAM_HMAC_ALG 32772
#define SCTP_PARAM_PADDING 32773
#define SCTP_PARAM_SUPPORT_EXT 32776
#define SCTP_PARAM_FORWARD_TSN 49152
#define SCTP_PARAM_ADD_IP 49153
#define SCTP_PARAM_DEL_IP 49154
#define SCTP_PARAM_ERROR_INDICATION 49155
#define SCTP_PARAM_SET_PRIMARY_ADDRESS 49156
#define SCTP_PARAM_SUCCESS_INDICATION 49157
#define SCTP_PARAM_ADAPTIVE_LAYER_INDICATION 49158


#endif /* sctpfuzz_h */
