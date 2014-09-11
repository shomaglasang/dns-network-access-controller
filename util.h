/*INC+*************************************************************************/
/* Filename    : util.h                                                       */
/*                                                                            */
/* Description : Utility routines header file.                                */
/*                                                                            */
/* Revisions   : 05/10/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _UTIL_H
#define _UTIL_H

#include <dns.h>

/******************************************************************************/
/* Forwards decls.                                                            */
/******************************************************************************/
extern char *trim_str(char *str);
extern int is_comment(char *str);
extern int dns_name_to_labels(char *name,
                         char label[DNS_MAX_NUM_LABELS][DNS_MAX_LABEL_LEN + 1]);
extern void dump_labels(char labels[DNS_MAX_NUM_LABELS][DNS_MAX_LABEL_LEN + 1],
                        int n);

#endif
