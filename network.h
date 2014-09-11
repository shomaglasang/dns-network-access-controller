/*INC+*************************************************************************/
/* Filename    : network.h                                                    */
/*                                                                            */
/* Description : Network routines header file.                                */
/*                                                                            */
/* Revisions   : 05/12/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _NETWORK_H
#define _NETWORK_H

/******************************************************************************/
/* Forwards decls.                                                            */
/******************************************************************************/
extern int create_net_listeners(int fam, int type, char *ip, int port,
                                SOCK_READER sock_reader);
extern int create_listeners(void);
extern void clean_listeners(void);
extern int map_listeners_fdset(void *ptr);
extern void check_listeners(void *ptr, int nfds);

#endif
