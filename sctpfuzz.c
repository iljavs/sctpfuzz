//
//  sctpfuzz.c
//  
//
//  Created by ilja van sprundel on 8/11/17.
//
//
//  Hacked this up during my summer break.
//  Might use this on a potential future engagement.
//
//  LICENSE: GPLv2
//
//  code inspired by isic.
//


// XXX TODO: implement the following
//                                  - add more specific parameter fuzzing (most is generic right now)
//                                  - add other chunk types ...


//  fix:
//          - small parameter (len 0-4) htons() fix. [DONE]
//          - delete IP / add IP parameter smart fuzzing (needs specific length)
//          - chunk padding [DONE]
//          - parameter padding [DONE]
//              - if last parameter, don't pad ...
//          - parameter error indiciation smart fuzzing (has embedded length)
//          - ipv4/ipv6 address parameter (just 1 ip ???? per parameter ?)
//          - hostname parameter fuzzing (long, short, dots, no dots, ips, no terminating 0-byte, fmt string issues)
//          - hmac algo parameter. add list of known HMAC identifiers
//          - unrecoginized parameter should be length 4 (no content)


#include "sctpfuzz.h"

// CRC32C code taken from: https://tools.ietf.org/html/rfc3309
/*************************************************************/
/* Note Definition for Ross Williams table generator would   */
/* be: TB_WIDTH=4, TB_POLLY=0x1EDC6F41, TB_REVER=TRUE        */
/* For Mr. Williams direct calculation code use the settings */
/* cm_width=32, cm_poly=0x1EDC6F41, cm_init=0xFFFFFFFF,      */
/* cm_refin=TRUE, cm_refot=TRUE, cm_xorort=0x00000000        */
/*************************************************************/

#define CRC32C_POLY 0x1EDC6F41
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])

unsigned long  crc_c[256] =
{
    0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
    0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
    0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
    0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
    0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
    0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
    0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
    0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
    0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
    0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
    0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
    0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
    0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
    0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
    0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
    0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
    0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
    0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
    0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
    0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
    0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
    0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
    0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
    0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
    0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
    0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
    0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
    0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
    0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
    0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
    0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
    0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
    0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
    0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
    0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
    0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
    0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
    0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
    0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
    0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
    0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
    0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
    0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
    0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
    0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
    0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
    0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
    0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
    0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
    0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
    0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
    0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
    0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
    0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
    0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
    0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
    0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
    0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
    0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
    0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
    0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
    0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
    0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
    0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L,
};

unsigned long
generate_crc32c(unsigned char *buffer, unsigned int length)
{
    unsigned int i;
    unsigned long crc32 = ~0L;
    unsigned long result;
    unsigned char byte0,byte1,byte2,byte3;
    
    for (i = 0; i < length; i++){
        CRC32C(crc32, buffer[i]);
    }
    result = ~crc32;
    
    /*  result  now holds the negated polynomial remainder;
     *  since the table and algorithm is "reflected" [williams95].
     *  That is,  result has the same value as if we mapped the message
     *  to a polynomial, computed the host-bit-order polynomial
     *  remainder, performed final negation, then did an end-for-end
     *  bit-reversal.
     *  Note that a 32-bit bit-reversal is identical to four inplace
     *  8-bit reversals followed by an end-for-end byteswap.
     *  In other words, the bytes of each bit are in the right order,
     *  but the bytes have been byteswapped.  So we now do an explicit
     *  byteswap.  On a little-endian machine, this byteswap and
     *  the final ntohl cancel out and could be elided.
     */
    
    byte0 = result & 0xff;
    byte1 = (result>>8) & 0xff;
    byte2 = (result>>16) & 0xff;
    byte3 = (result>>24) & 0xff;
    crc32 = ((byte0 << 24) |
             (byte1 << 16) |
             (byte2 << 8)  |
             byte3);
    return ( crc32 );
}

void help(char *prog) {
    printf("%s\t[-h] -s <source ip> -d <dest ip> [-c <random seed>] \n", prog);
    printf("\t\t[-S <source port>] [-D <dest port>] [-p <max num of sctp params>]\n");
    printf("\t\t[-n <number of packets to generate>] [-k <skip packets>]\n");
    printf("\t\t[-t <time to wait in microseconds between each packet>]\n");
    exit(0);
}

unsigned int get_offset(unsigned char *begin, unsigned char *end) {
    return end - begin;
}

void validate_ip(char *ip) {
    char part[4] = {0};
    int partidx = 0;
    int sepidx = 0;
    while(*ip != '\0') {
        if (*ip != '0' && *ip != '1' && *ip != '2' && *ip != '3' && *ip != '4' && *ip != '5' && \
            *ip != '6' && *ip != '7' && *ip != '8' && *ip != '9' && *ip != '.') {
            printf("[1] not valid ip address\n");
            exit(0);
        }
        if (*ip == '.') {
            sepidx++;
            if (partidx == 0) {
                printf("[2] not valid ip address\n");
                exit(0);
            }
            part[partidx] = '\0';
            partidx = 0;
            int num = atoi(part);
            if (num < 0 || num > 255) {
                printf("[3] not valid up address\n");
            }
            
        } else {
            if (partidx > 2) {
                printf("[4] not valid ip address\n");
                exit(0);
            }
            part[partidx++] = *ip;
        }
        ip++;
    }
    
    if (sepidx != 3) {
        printf("[5] not valid ip address\n");
        exit(0);
    }

    if (partidx == 0) {
        printf("[6] not valid ip address\n");
        exit(0);
    }
    
    part[partidx] = '\0';
    partidx = 0;
    int num = atoi(part);
    if (num < 0 || num > 255) {
        printf("[7] not valid up address\n");
    }

    return;
}

struct args parse_arguments(int argc, char **argv) {
    int c;

    char *prog = argv[0];
    
    // this shuts up clang, but might not be portable. {0} is more portable, but clang (-Wextra) whines about it.
    struct args a = {};
    
    while ((c = getopt (argc, argv, "hs:d:c:n:S:D:p:t:k:")) != -1) {
        switch (c) {
            case 's':
                a.source = strdup(optarg);
                if (a.source == NULL) {
                    printf("strdup failed\n");
                    exit(0);
                }
                validate_ip(a.source);
                break;
            case 'd':
                a.dest = strdup(optarg);
                if (a.dest == NULL) {
                    printf("strdup failed\n");
                    exit(0);
                }
                validate_ip(a.dest);
                break;
            case 'h':
                help(prog);
                break;
            case 'c':
                a.seed = atoi(optarg);
                break;
            case 'n':
                a.nr_packets = atoi(optarg);
                break;
            case 'S':
                a.sport = atoi(optarg);
                break;
            case 'D':
                a.dport = atoi(optarg);
                break;
            case 'p':
                a.max_nr_params = atoi(optarg);
                break;
            case 't':
                a.timeout = atoi(optarg);
                break;
            case 'k':
                a.skip = atoi(optarg);
                if (a.skip < 0) {
                    printf("skip has to be a positive number\n");
                    exit(0);
                }
                break;
        }
    }

    if (a.source == NULL || a.dest == NULL) {
        printf("need to specify a source and a destination. use -h switch for help\n");
        exit(0);
    }
    return a;
}

// XXX TODO: lookup nobody, fail open if he doesn't exist. do same for group ? (nobody, nogroup)
void priv_drop() {

}

// XXX TODO: add privdrop ? to what? nobody ?
int get_raw_socket () {
    int one = 1;
    const int *val = &one;
    
    int fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        printf("Raw socket creation failed\n");
        exit(0);
    }

    priv_drop();
    
    if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        close(fd);
        printf("setsockopt hdrinclude failed\n");
        exit(0);
    }
    
    return fd;
}

int get_max_loop(struct args *pargs) {
    if (pargs->nr_packets) return pargs->nr_packets;
    return LOOP_NR;
}

int get_packet_len() {
    return PACKET_SIZE;
}

unsigned char *fill_ip(unsigned char *p, struct args *pargs) {
    struct iphdr *ip = (struct iphdr*) p;
    ip->v_hdrlen = 4;
    ip->v_hdrlen <<= 4;
    ip->v_hdrlen |= 5; // 20 bytes
    ip->tos = 0;
    ip->tot_len = 0; // update later
    ip->id = rand();
    ip->frag_off = 0;
    ip->ttl = 128;
    ip->protocol = 132; // IANA says thats the number: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    ip->check = 0;
    ip->saddr = inet_addr(pargs->source);
    ip->daddr = inet_addr(pargs->dest);
    
    p += sizeof(struct iphdr);
    return p;
    
}

unsigned int rand_params(struct args *pargs) {
    
    if (pargs->max_nr_params)
        return (rand() % pargs->max_nr_params) + 1;
    else
        return (rand() % 5) + 1;
}

unsigned int get_rand_bytes(unsigned char *p, unsigned int len) {
    
    unsigned int *ip = (unsigned int *)p;
    unsigned int i;
    for (i = 0; i < len/4; i++) {
        *ip++ = rand();
    }
    
    unsigned int remain = len % 4;
    if (remain == 1) {
        unsigned char *c = (unsigned char *) ip;
        *c = rand();
    } else if (remain == 2) {
        unsigned short *s = (unsigned short *) ip;
        *s = rand();
    } else if (remain == 3) {
        unsigned short *s = (unsigned short *) ip;
        *s++ = rand();
        unsigned char *c = (unsigned char *) s;
        *c = rand();
    }
    
    return len;
}


unsigned int align(unsigned int amt) {
    return amt + ((4 - (amt % 4)) % 4);
}

unsigned short fuzz_len[] = {0,4, 0xf, 0x3f, 0x40, 0x41, 0x7f, 0x80, 0x81, 0xff, 0x1ff, 0x3fff, 0x4000, 0x4001, 0x7fff, 0x8000, 0x8001, 0xffff};

unsigned int mutate_length(unsigned int len) {
    
    unsigned int delta = 0;

    len += 4; // len + 4 (to account for header)
    if (rand() % 100) {
        return len;
//        len = /*align(*/len/*)*/;   // don't do alignment at all
    } else {
        switch(rand() % 6) {  // we should add an alignment case here
            case 0:  // leave as is, no alignment
                break;
            case 1: // smaller
                len = rand() % len;
                break;
            case 2: // larger
                len = len + rand() % 1000;
                break;
            case 3: // fuzz lens
                len = fuzz_len[ rand() % (sizeof(fuzz_len) / sizeof(fuzz_len[0])) ];
                break;
            case 4: //small deltas
            case 5:
                delta = rand() % 10;
                if (rand() % 2) {
                    len += delta;
                } else {
                    len -= delta;
                }
                break;
        }
    }

    return len;
}

unsigned int param_length(unsigned char *begin, unsigned char *end) {
    unsigned int len = get_offset(begin, end);
    len = mutate_length(len);
    return htons(len);
}

unsigned char *padd_bytes(unsigned char *pcur, unsigned int len) {

    if (rand() % 100) {  // padding
        
        unsigned int remain = len % 4;
        unsigned char r[4];
        unsigned int *ri = (unsigned int *)r;
        
        if (remain == 1) {  // 3 pad bytes
            switch(rand() % 100) {
                case 0:
                    *ri = rand();
                    *pcur++ = r[0];
                    *pcur++ = r[1];
                    *pcur++ = r[2];
                    break;
                default:
                    *pcur++ = '\0';
                    *pcur++ = '\0';
                    *pcur++ = '\0';
                    break;
            }
        } else if (remain == 2) { // 2 pad bytes
            switch(rand() % 100) {
                case 0:
                    *ri = rand();
                    *pcur++ = r[0];
                    *pcur++ = r[1];
                    break;
                default:
                    *pcur++ = '\0';
                    *pcur++ = '\0';
                    break;
            }
        } else if (remain == 3) { // 1 pad byte
            switch(rand() % 100) {
                case 0:
                    *ri = rand();
                    *pcur++ = r[0];
                    break;
                default:
                    *pcur++ = '\0';
                    break;
            }
            
        }
        
    }
    return pcur;
}

unsigned char *fill_generic(unsigned char *p) {
    
    unsigned int len = rand() % 200;
    
    struct sctp_init_param *sip = (struct sctp_init_param *)p;
    unsigned char *pcur = (unsigned char *) (sip+1);
    unsigned char *pbegin = pcur;
    
    pcur += get_rand_bytes(pcur, len);
    
    sip->len = param_length(pbegin, pcur);
    unsigned int tlen = htons(sip->len);
    pcur = padd_bytes(pcur, tlen);

    return pcur;
    
}

unsigned char *fill_sctp_param_heartbeat(unsigned char * p) {
    //printf("fill_sctp_param_heartbeat\n");
    
    struct sctp_init_param *sip = (struct sctp_init_param *)p;
    unsigned char *hb_data = (unsigned char *) (sip+1);
    unsigned char *pcur = hb_data;
    
    unsigned int len = rand() % 100;
    pcur += get_rand_bytes(hb_data, len);
    sip->len = param_length(hb_data, pcur);

    unsigned int tlen = htons(sip->len);
    pcur = padd_bytes(pcur, tlen);
    
    return pcur;
}

// XXX TODO: add more ips ?
char *ips[] = {"127.0.0.1", "10.0.0.2", "192.168.3.65", "0.0.0.0", "255.255.255.255", "172.16.0.1", "172.16.0.0"};

unsigned char *gen_ipv4(unsigned char *p) {
    unsigned int *ip = (unsigned int *) p;
    if (rand() % 10) {
        *ip++ = rand();
    
    } else {
        *ip++ = inet_addr( ips[ rand() % (sizeof(ips) / sizeof(ips[0])) ] );
    }
    return (unsigned char *)ip;
}

// XXX TODO: add more ips
unsigned char *gen_ipv6(unsigned char *p) {
    p += get_rand_bytes(p, 16);
    return p;
}

unsigned int gen_nr_ips() {
    unsigned int nr_ips = 0;
    
    if (rand() % 100) {
        nr_ips = rand() % 10 + 1;
    } else {
        if (rand() % 1000) {
            nr_ips = rand() % 100 + 1;
        } else if (rand() % 100) {
            nr_ips = rand() % 1000;
        } else {
            nr_ips = rand() % 10000;
        }
    }
    return nr_ips;
}

unsigned char *fill_sctp_param_ipv4(unsigned char *p) {
//    printf("fill_sctp_param_ipv4\n");
    
    unsigned int i, nr_ips = gen_nr_ips();
    
    struct sctp_init_param *sip = (struct sctp_init_param *)p;
    unsigned char *pcur = (unsigned char *) (sip+1);
    unsigned char *pbegin = pcur;
    
    for (i = 0; i < nr_ips; i++) {
        pcur = gen_ipv4(pcur);
    }
    
    sip->len = param_length(pbegin, pcur);
    
    unsigned int tlen = htons(sip->len);
    pcur = padd_bytes(pcur, tlen);

    
    return pcur;
}

unsigned char *fill_sctp_param_ipv6(unsigned char * p) {
//    printf("fill_sctp_param_ipv6\n");
    
    unsigned int i, nr_ips = gen_nr_ips();
    
    struct sctp_init_param *sip = (struct sctp_init_param *)p;
    unsigned char *pcur = (unsigned char *) (sip+1);
    unsigned char *pbegin = pcur;
    
    for (i = 0; i < nr_ips; i++) {
        pcur = gen_ipv6(pcur);
    }
    
    sip->len = param_length(pbegin, pcur);
    
    unsigned int tlen = htons(sip->len);
    pcur = padd_bytes(pcur, tlen);

    return pcur;

}

unsigned char *fill_sctp_param_state_cookie(unsigned char * p) {
//    printf("fill_sctp_param_state_cookie\n");
    
    unsigned int len = rand() % 200;

    struct sctp_init_param *sip = (struct sctp_init_param *)p;
    unsigned char *pcur = (unsigned char *) (sip+1);
    unsigned char *pbegin = pcur;

    pcur += get_rand_bytes(pcur, len);
    
    sip->len = param_length(pbegin, pcur);
    
    unsigned int tlen = htons(sip->len);
    pcur = padd_bytes(pcur, tlen);

    return pcur;
}

unsigned char *fill_sctp_param_unrecognized_param(unsigned char * p) {
//    printf("fill_sctp_param_unrecognized_param\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_cookie_preservative(unsigned char * p) {
//    printf("fill_sctp_param_cookie_preservative\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_hostname(unsigned char * p) {
//    printf("fill_sctp_param_hostname\n");
    return fill_generic(p);

}

unsigned short address_types[] = {5,6,11};

unsigned short get_valid_address_type() {
    return address_types[ rand() % (sizeof(address_types) / sizeof(address_types[0]) ) ];
}

// XXX TODO: complete this code 
unsigned char *fill_sctp_param_address_types(unsigned char * p) {
//    printf("fill_sctp_param_address_types\n");
    
    int i, nr_types = 0;
    if (rand() % 5) {
        nr_types = (rand() % 3) + 1;
        for (i = 0; i < nr_types; i++) {
            unsigned short type = get_valid_address_type();
            
        }
        
    }
    
    return fill_generic(p);

}

unsigned char *fill_sctp_param_out_ssn(unsigned char * p) {
//    printf("fill_sctp_param_out_ssn\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_in_ssn(unsigned char * p) {
//    printf("fill_sctp_param_in_ssn\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_ssn_reset(unsigned char * p) {
//    printf("fill_sctp_param_ssn_reset\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_reconfigure_response(unsigned char * p) {
//    printf("fill_sctp_param_reconfigure_response\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_add_out_request(unsigned char * p) {
//    printf("fill_sctp_param_add_out_request\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_add_in_request(unsigned char * p) {
//    printf("fill_sctp_param_add_in_request\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_ecn(unsigned char * p) {
//    printf("fill_sctp_param_ecn\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_rand(unsigned char * p) {
//    printf("fill_sctp_param_rand\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_chunk_list(unsigned char * p) {
//    printf("fill_sctp_param_chunk_list\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_hmac_alg(unsigned char * p) {
//    printf("fill_sctp_param_hmac_alg\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_padding(unsigned char * p) {
//    printf("fill_sctp_param_padding\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_support_ext(unsigned char * p) {
//    printf("fill_sctp_param_support_ext\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_forward_tsn(unsigned char * p) {
//    printf("fill_sctp_param_forward_tsn\n");
    return fill_generic(p);

}
unsigned char *fill_sctp_param_add_ip(unsigned char * p) {
//    printf("fill_sctp_param_add_ip\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_del_ip(unsigned char * p) {
//    printf("fill_sctp_param_del_ip\n");
    return fill_generic(p);

}

// XXX TODO: add code here (e.g. embedded length field)
unsigned char *fill_sctp_param_error_indication(unsigned char * p) {
//    printf("fill_sctp_param_error_indication\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_set_primary_address(unsigned char * p) {
//    printf("fill_sctp_param_set_primary_address\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_success_indication(unsigned char * p) {
//    printf("fill_sctp_param_success_indication\n");
    return fill_generic(p);

}

unsigned char *fill_sctp_param_adaptive_layer_indication(unsigned char * p) {
//    printf("fill_sctp_param_adaptive_layer_indication\n");
    return fill_generic(p);

}


struct sctp_param_handlers {
    unsigned int type;
    unsigned char * (*fn)(unsigned char *);
} sctp_params[] = {
    {SCTP_PARAM_HEARTBEAT, &fill_sctp_param_heartbeat},
    {SCTP_PARAM_IPv4, &fill_sctp_param_ipv4},
    {SCTP_PARAM_IPv6, &fill_sctp_param_ipv6},
    {SCTP_PARAM_STATE_COOKIE, &fill_sctp_param_state_cookie},
    {SCTP_PARAM_UNRECOGNIZED_PARAM, &fill_sctp_param_unrecognized_param},
    {SCTP_PARAM_COOKIE_PRESERVATIVE, &fill_sctp_param_cookie_preservative},
    {SCTP_PARAM_HOSTNAME, &fill_sctp_param_hostname},
    {SCTP_PARAM_ADDRESS_TYPES, &fill_sctp_param_address_types},
    {SCTP_PARAM_OUT_SSN, &fill_sctp_param_out_ssn},
    {SCTP_PARAM_IN_SSN, &fill_sctp_param_in_ssn},
    {SCTP_PARAM_SSN_RESET, &fill_sctp_param_ssn_reset},
    {SCTP_PARAM_RECONFIG_RESPONSE, &fill_sctp_param_reconfigure_response},
    {SCTP_PARAM_ADD_OUT_REQUEST, &fill_sctp_param_add_out_request},
    {SCTP_PARAM_ADD_IN_REQUEST, &fill_sctp_param_add_in_request},
    {SCTP_PARAM_ECN, &fill_sctp_param_ecn},
    {SCTP_PARAM_RAND, &fill_sctp_param_rand},
    {SCTP_PARAM_CHUNK_LIST, &fill_sctp_param_chunk_list},
    {SCTP_PARAM_HMAC_ALG, &fill_sctp_param_hmac_alg},
    {SCTP_PARAM_PADDING, &fill_sctp_param_padding},
    {SCTP_PARAM_SUPPORT_EXT, &fill_sctp_param_support_ext},
    {SCTP_PARAM_FORWARD_TSN, &fill_sctp_param_forward_tsn},
    {SCTP_PARAM_ADD_IP, &fill_sctp_param_add_ip},
    {SCTP_PARAM_DEL_IP, &fill_sctp_param_del_ip},
    {SCTP_PARAM_ERROR_INDICATION, &fill_sctp_param_error_indication},
    {SCTP_PARAM_SET_PRIMARY_ADDRESS, &fill_sctp_param_set_primary_address},
    {SCTP_PARAM_SUCCESS_INDICATION, &fill_sctp_param_success_indication},
    {SCTP_PARAM_ADAPTIVE_LAYER_INDICATION, &fill_sctp_param_adaptive_layer_indication}
};

unsigned char *fill_param(unsigned char *p) {
    
    struct sctp_init_param *sip = (struct sctp_init_param *)p;
    unsigned int max_params = sizeof(sctp_params) / sizeof(sctp_params[0]);
    unsigned int pidx = rand() % max_params;
    
    sip->type = htons (sctp_params[pidx].type);
    if (!(rand() % 100)) {
        unsigned int pct = rand() % 100;
        if (pct < 80) {
            sip->len = htons(4);
        } else if (pct < 97) {
            sip->len = htons(0);
        } else if (pct == 97) {
            sip->len = htons(1);
        } else if (pct == 98) {
            sip->len = htons(2);
        } else if (pct == 99) {
            sip->len = htons(3);
        }
        return (unsigned char *) (sip+1);
    } else {
        return sctp_params[pidx].fn(p);
    }
}

unsigned char fuzz_chunk_flags() {
    if (rand() % 20) {
        return 0;
    }
    if (rand() % 10) {
        return rand() % 2;
    }
    if (rand() % 10) {
        return rand() % 16;
    }
    return rand();
}

unsigned char *fill_sctp(unsigned char *p, struct args *pargs) {

    struct sctp_comm_hdr *sch = (struct sctp_comm_hdr *)p;
    sch->sport = pargs->sport ? htons(pargs->sport) : htons(DEFAULT_SPORT);
    sch->dport = pargs->dport ? htons(pargs->dport) : htons(DEFAULT_DPORT);
    sch->tag = 0;
    sch->check = 0; // fix up later
    
    struct sctp_chunk_hdr *chunkhdr = (struct sctp_chunk_hdr *) (sch + 1);
    
    chunkhdr->type = SCTP_INIT;
    chunkhdr->flags = fuzz_chunk_flags();
    chunkhdr->len = 0;  // fix up later
    
    struct sctp_init_chunk *sic =  (struct sctp_init_chunk *) (chunkhdr+1);
    sic->tag = rand();
    sic->window_credit = htonl(rand() % 200000);
    sic->oob_streams = htons(rand() % 200);
    sic->iob_streams = htons(rand());
    sic->tsn = rand();
    
    
    unsigned int nr_chunks = rand_params(pargs);
    unsigned int i;
    unsigned char *pcur = (unsigned char *) (sic+1);
    
    
    
    for (i = 0; i < nr_chunks; i++) {
       //(nr_chunks - i == 1)
        pcur = fill_param(pcur);
    }
    
    // fix checksum and chunk length
    unsigned int len = get_offset((unsigned char *)chunkhdr, pcur);
    chunkhdr->len = htons(len);
    unsigned int clen = len;
    
    len = get_offset(p, pcur);
    unsigned int crc32 = generate_crc32c(p,len);
    sch->check = htonl(crc32);
    
    pcur = padd_bytes(pcur, clen);
    return pcur;
}

void update_ip(unsigned char *p, unsigned int len) {
    struct iphdr *ip = (struct iphdr *) p;
    ip->tot_len = len;
    // XXX TODO: do ip checksum calculation here tooo (or not? kernel does fixup?)
    return;
}

unsigned int get_seed() {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        printf("couldn't open /dev/urandom\n");
        exit(0);
    }
    
    unsigned int seed;

    int r = read(fd, &seed, sizeof(seed));

    if (r != sizeof(seed)) {
        printf("not enough data read from /dev/urandom");
        exit(0);
    }
    
    close(fd);
    return seed;
}

unsigned int g_seed = 0;
unsigned long g_acx = 0;
struct timeval g_starttime;
u_long g_datapushed = 0;			/* How many bytes we pushed */
unsigned int g_nobufs = 0;
unsigned int g_timedout = 0;

void sighandler(int sig)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    printf("\n");
    printf("Caught signal %i\n", sig);
    
    printf("Used random seed %i\n", g_seed);
    
    printf("ETIMEDOUTs: %u\n", g_timedout);
    printf("ENOBUFS: %u\n", g_nobufs);
    
    printf("Wrote %li packets in %.2fs @ %.2f pkts/s\n", g_acx,
           (tv.tv_sec - g_starttime.tv_sec)
           + (tv.tv_usec - g_starttime.tv_usec)/1000000.0,
           g_acx / (( tv.tv_sec - g_starttime.tv_sec)
                  + (tv.tv_usec - g_starttime.tv_usec)/1000000.0)
           );
    
    fflush(stdout);
    exit(0);
}

void install_sig_handlers() {
    printf("Installing Signal Handlers.\n");
    if ( signal(SIGTERM, &sighandler) == SIG_ERR ) {
        printf("Failed to install signal handler for SIGTERM\n");
        exit(0);
    }
    if ( signal(SIGINT, &sighandler) == SIG_ERR ){
        printf("Failed to install signal handler for SIGINT\n");
        exit(0);
    }
    if ( signal(SIGQUIT, &sighandler) == SIG_ERR ){
        printf("Failed to install signal handler for SIGQUIT\n");
        exit(0);
    }
    return;
}

// reporting code taken from isic
void report_progress(int i, struct timeval *tv, unsigned long *datapushed) {

    struct timeval tv2;
    float sec;
    
    if ( !(i % 1000) ) {
        if ( i == 0 )
            return;
        gettimeofday(&tv2, NULL);
        sec = (tv2.tv_sec - tv->tv_sec)
        - (tv->tv_usec - tv2.tv_usec) / 1000000.0;
        printf(" %i @ %.1f pkts/sec and %.1f k/s\n", i,
               1000/sec, (*datapushed / 1024.0) / sec);
        *datapushed=0;
        gettimeofday(tv, NULL);
    }
    
    g_acx = i;
    return;
}

// reporting code taken from isic
void report_final_progress(unsigned int timedout, unsigned int nobufs, int i, struct timeval starttime) {
    struct timeval tv;
    printf("\nETIMEDOUTs: %u\n", timedout);
    printf("ENOBUFSs: %u\n", nobufs);
    gettimeofday(&tv, NULL);
    printf("\nWrote %i packets in %.2fs @ %.2f pkts/s\n", i,
           (tv.tv_sec-starttime.tv_sec)
           + (tv.tv_usec-starttime.tv_usec) / 1000000.0,
           i / ((tv.tv_sec-starttime.tv_sec)
                + (tv.tv_usec-starttime.tv_usec)/1000000.0) );

    return;
}

void hanlde_sendto_retval(int r, unsigned int *nobufs, unsigned int *timedout, unsigned long *datapushed) {
    if (r == -1) {
        if (errno == ENOBUFS) {
            *nobufs += 1;
            g_nobufs++;
        } else if (errno == ETIMEDOUT) {
            *timedout += 1;
            g_timedout++;
        }
    } else {
        *datapushed += r;
        g_datapushed = *datapushed;
    }
    return;
}

void init_sockaddrin(struct sockaddr_in *sin, struct args args) {
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr.s_addr = inet_addr(args.dest);
    memset(sin->sin_zero, 0, sizeof(sin->sin_zero));

}

void *xmalloc(size_t len) {
    void *p = malloc(len);
    if (p == NULL) {
        printf("malloc failed\n");
        exit(0);
    }
    return p;
}

unsigned int get_timeout(struct args *a) {
    if (!a->timeout) {
        return SENTO_TIMEOUT;
    }
    return a->timeout;
}

int sendto_skip(int sock, unsigned char *data, unsigned int packetlen, unsigned int flags, struct sockaddr *sin, unsigned int sinlen, int i, int skip) {
    int r;
    if (skip <= i) {
        r = sendto(sock, data, packetlen, flags, sin, sinlen);
    } else {
        r = packetlen;
    }
    return r;
}

void usleep_skip(useconds_t microseconds, int i, int skip) {
    if (skip <= i) { // only sleep if we're not skipping anything
        usleep(microseconds); // artificial delay ... else the kernel (osx) complains too much (ETIMEDOUT, ENOBUFS)
    }
    return;
}

int main(int argc, char **argv) {
    struct args args;
    struct sockaddr_in sin;
    struct timeval starttime, tv;
    unsigned long datapushed = 0;
    int i, r;
    unsigned int nobufs = 0;
    unsigned int timedout = 0;

    args = parse_arguments(argc, argv);
    install_sig_handlers();
    
    int sock = get_raw_socket();
    int max = get_max_loop(&args);

    unsigned int packet_len = get_packet_len();
    unsigned int sendto_timeout = get_timeout(&args);
    unsigned char *data = xmalloc(packet_len);
    unsigned int seed = args.seed ? args.seed : get_seed();
    g_seed = seed;
    srand(seed);

    printf("using seed: %u\n", seed);
    init_sockaddrin(&sin, args);
    
    gettimeofday(&tv, NULL);
    g_starttime = starttime = tv;
    
    for (i = 0; i < max; i++) {
        unsigned char *pcur;
        pcur = fill_ip(data, &args);
        pcur = fill_sctp(pcur, &args);
        unsigned int packetlen = get_offset(data, pcur);
        update_ip(data, packetlen);
        r = sendto_skip(sock, data, packetlen, 0, (struct sockaddr *)&sin, sizeof(sin), i, args.skip);
        hanlde_sendto_retval(r, &nobufs, &timedout, &datapushed);
        report_progress(i, &tv, &datapushed);
        usleep_skip(sendto_timeout, i, args.skip);
    }
    
    report_final_progress(timedout, nobufs, i, starttime);
    free(data);
}
