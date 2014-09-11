/*INC+*************************************************************************/
/* Filename    : dns.h                                                        */
/*                                                                            */
/* Description : DNS protocol.                                                */
/*                                                                            */
/* Revisions   : 05/17/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _DNS_H
#define _DNS_H

/******************************************************************************/
/* DNS contants.                                                              */
/******************************************************************************/
#define DNS_PAYLOADZ                              512
#define DNS_MAX_NAME_LEN                          253
#define DNS_MAX_LABEL_LEN                         63
#define DNS_MAX_NUM_LABELS                        127
#define DNS_MAX_ANS_RR_NUM                        5
#define DNS_MAX_ANS_RR_LEN                        255

#define DNS_MAX_DEFAULT_TTL                       0

/******************************************************************************/
/* DNS header bit flags.                                                      */
/******************************************************************************/
#define DNS_HDR_QR                                0x80
#define DNS_HDR_OPCODE                            0x78
#define DNS_HDR_AA                                0x04
#define DNS_HDR_TC                                0x02
#define DNS_HDR_RD                                0x01
#define DNS_HDR_RA                                0x80
#define DNS_HDR_RC                                0x0F

#define DNS_HDR_QR_RESP                           0x80
#define DNS_HDR_RCODE_NO_ERR                      0x0
#define DNS_HDR_RCODE_FORMAT_ERR                  0x1
#define DNS_HDR_RCODE_SERVER_FAILURE              0x2
#define DNS_HDR_RCODE_NAME_ERR                    0x3
#define DNS_HDR_RCODE_NOT_IMPL                    0x4
#define DNS_HDR_RCODE_REFUSED                     0x5

/******************************************************************************/
/* DNS RR types.                                                              */
/******************************************************************************/
#define DNS_RR_TYPE_A                             1
#define DNS_RR_TYPE_NS                            2
#define DNS_RR_TYPE_CNAME                         5
#define DNS_RR_TYPE_SOA                           6
#define DNS_RR_TYPE_PTR                           12
#define DNS_RR_TYPE_MX                            15

#define DNS_RR_TYPE_A_LEN                         4

/******************************************************************************/
/* DNS RR class.                                                              */
/******************************************************************************/
#define DNS_RR_CLASS_IN                           1

/******************************************************************************/
/* DNS header structure.                                                      */
/******************************************************************************/
typedef struct _dns_header { 
  unsigned short id;
  unsigned short fc;
  unsigned short q_count;
  unsigned short ans_count;
  unsigned short ns_count;
  unsigned short addrec_count;
} dns_header;

#endif

