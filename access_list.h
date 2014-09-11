/*INC+*************************************************************************/
/* Filename    : access_list.h                                                */
/*                                                                            */
/* Description : Access list related definitions, structs, whitelist, etc.    */
/*                                                                            */
/* Revisions   : 06/03/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _ACCESS_LIST_H
#define _ACCESS_LIST_H

/******************************************************************************/
/* Includes.                                                                  */
/******************************************************************************/
#include <time.h>

#include <llist.h>


/******************************************************************************/
/* ACL status.                                                                */
/******************************************************************************/
#define ACL_OK                                    0
#define ACL_GEN_ERR                               1
#define ACL_ADD_ALLOW_RULE_ERR                    2
#define ACL_DEL_ALLOW_RULE_ERR                    3
#define ACL_ADD_BLOCK_RULE_ERR                    4
#define ACL_DEL_BLOCK_RULE_ERR                    5

/******************************************************************************/
/* Constants.                                                                 */
/******************************************************************************/
#define ACCESS_LIST_HASH_SIZE                     12

/******************************************************************************/
/* Source/dest ACL entry.                                                     */
/* - For enhancement: Balance tree or dijkstra for faster lookup.             */
/******************************************************************************/
typedef struct _src_dest_cb
{
  struct _src_dest_cb *next;
  unsigned int src;
  unsigned int dst;
  int ref_count;
  unsigned long age;
  time_t created_at;
  time_t expiry;
  int last_status;
} src_dest_cb;


/******************************************************************************/
/* Source-dest ACL.                                                           */
/******************************************************************************/
typedef struct _src_dest_acl
{
  llist h[ACCESS_LIST_HASH_SIZE];
} src_dest_acl;


/******************************************************************************/
/* Forwards decls.                                                            */
/******************************************************************************/
extern int create_start_acl_sweeper(void);
extern void wait_acl_sweeper(void);
extern int add_src_dest_to_whitelist(void *src_addr, dns_question *qs,
                                     int n_qs);
extern int del_src_dest_whitelist(unsigned int src, unsigned int dst);
extern void clean_src_dest_whitelist(void);
extern int create_whitelist_from_fw_rules(void);

#endif
