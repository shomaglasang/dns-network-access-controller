/*INC+*************************************************************************/
/* Filename    : dnswldcb.h                                                   */
/*                                                                            */
/* Description : DNS Whitelist daemon data structure definition and constants.*/
/*                                                                            */
/* Revisions   : 05/10/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _DNSWLDCB_H
#define _DNSWLDCB_H

/******************************************************************************/
/* Includes.                                                                  */
/******************************************************************************/
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/******************************************************************************/
/* Constants.                                                                 */
/******************************************************************************/
#ifdef IF_NAMESIZE
#define IF_NAME_MAX_LEN                           IF_NAMESIZE
#else
#define IF_NAME_MAX_LEN                           16
#endif

#define IP4_STR_MAX_LEN                           15
#define PORT_STR_MAX_LEN                          6
#define PROC_NAME_MAX_LEN                         15
#define FILENAME_MAX_LEN                          255

#define FW_CHAIN_MAX_LEN                          50
#define FW_CHAIN_MAX_NUM                          5

#define DEF_DNSWLD_PORT                           53
#define DEF_DNSWLD_IP4                            "0.0.0.0"
#define DEF_WHITELIST_AGE                         300
#define DEF_CONFIG_FILE                           "/etc/dnswld.cfg"


/******************************************************************************/
/* Socket reader callback function date type.                                 */
/******************************************************************************/
typedef int (*SOCK_READER)(void *listener);

/******************************************************************************/
/* Listeners CB.                                                              */
/******************************************************************************/
typedef struct _listeners_cb
{
  struct _listeners_cb *next;
  int sock;
  int port;
  struct in_addr addr4;
  char addr4_str[IP4_STR_MAX_LEN];
  char if_name[IF_NAME_MAX_LEN];
  SOCK_READER sock_reader;
} listeners_cb;


/******************************************************************************/
/* Logging CB.                                                                */
/******************************************************************************/
typedef struct _logging_cb
{
  int is_debug_on;
  int facility;
} logging_cb;


/******************************************************************************/
/* Proccess CB.                                                               */
/******************************************************************************/
typedef struct _process_cb
{
  char proc_name[PROC_NAME_MAX_LEN];
  char config_file[FILENAME_MAX_LEN];
  pid_t pid;
  int is_daemon;
  int is_running;
  char *pkt_buf;
  int pkt_bufz;
  int wl_age;
  int disable_fw;
  int disable_cmd_channel;
  char cmd_buf[CMD_PAYLOADZ];
  char cmd_ip[IP4_STR_MAX_LEN];
  int cmd_port;
} process_cb;


/******************************************************************************/
/* Data stores.                                                               */
/******************************************************************************/
typedef struct _data_store
{
  dnt_node *whitelist;
  dnt_node *blacklist;
} data_store;


/******************************************************************************/
/* ACL CB.                                                                    */
/******************************************************************************/
typedef struct _acl_cb
{
  src_dest_acl ll;
} acl_cb;


/******************************************************************************/
/* Firewall CB.                                                               */
/******************************************************************************/
typedef struct _fw_cb
{
  int n_chains;
  char chains[FW_CHAIN_MAX_NUM][FW_CHAIN_MAX_LEN];
  char iptables_path[FILENAME_MAX_LEN];
} fw_cb;


/******************************************************************************/
/* DNS Whitelist daemon control block.                                        */
/******************************************************************************/
typedef struct _dnswld_cb
{
  process_cb proc;
  logging_cb log;
  llist listeners;
  data_store ds;
  acl_cb acl;
  fw_cb fw;
} dnswld_cb;


/******************************************************************************/
/* Global daemon control block.                                               */
/******************************************************************************/
extern dnswld_cb dnswld;
extern char prog_name[PROC_NAME_MAX_LEN];

/******************************************************************************/
/* External decls.                                                            */
/******************************************************************************/
extern void init_dnswld(void);
extern int init_dns_bufs(void);
extern void clean_dns_bufs(void);
extern int init_data_stores(void);
extern void clean_ds_stores(void);

#endif
