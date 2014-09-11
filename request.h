/*INC+*************************************************************************/
/* Filename    : request.h                                                    */
/*                                                                            */
/* Description : Header file for DNS request processing routines.             */
/*                                                                            */
/* Revisions   : 05/23/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _REQUEST_H
#define _REQUEST_H

/******************************************************************************/
/* Forwards decls.                                                            */
/******************************************************************************/
extern int process_requested_domains(void *src_addr, dns_question *qs,
                                     int n_qs);

#endif
