/*INC+*************************************************************************/
/* Filename    : response.h                                                   */
/*                                                                            */
/* Description : Header file for DNS response processing routines.            */
/*                                                                            */
/* Revisions   : 05/29/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _RESPONSE_H
#define _RESPONSE_H

/******************************************************************************/
/* Forwards decls.                                                            */
/******************************************************************************/
extern int process_response(listeners_cb *listener, struct sockaddr_in *d_addr,
                            char *last, dns_header *dns_hdr, dns_question *q);
#endif
