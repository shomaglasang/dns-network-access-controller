/*INC+*************************************************************************/
/* Filename    : cmd_api.h                                                    */
/*                                                                            */
/* Description : Command API related structs, defines, etc.                   */
/*                                                                            */
/* Revisions   : 06/11/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _CMD_API_H
#define _CMD_API_H


/******************************************************************************/
/* Constants                                                                  */
/******************************************************************************/
#define DEF_CMD_IP                                "127.0.0.1"
#define DEF_S_CMD_PORT                            12353
#define DEF_C_CMD_PORT                            12352
#define DEF_CMD_TIMEOUT                           5
#define CMD_PAYLOADZ                              512
#define CMD_FILENAME                              "dnswld"

/******************************************************************************/
/* Command IDs                                                                */
/******************************************************************************/
#define CMD_NONE                                  0
#define CMD_STATUS                                1
#define CMD_START                                 2
#define CMD_STOP                                  3
#define CMD_GET_WHITELIST_DOMAIN                  4
#define CMD_GET_WHITELIST_IP                      5
#define CMD_DEL_WHITELIST_IP                      6

/******************************************************************************/
/* Command Types.                                                             */
/******************************************************************************/
#define CMD_REQUEST                               1
#define CMD_RESPONSE                              2

/******************************************************************************/
/* Command header structure                                                   */
/******************************************************************************/
typedef struct _cmd_hdr
{ 
  char type;
  char cmd_id;
  unsigned short req_id;
} cmd_hdr;


/******************************************************************************/
/* Objects                                                                    */
/******************************************************************************/
typedef struct _proc_status_obj
{
  int pid;
} proc_status_obj;


typedef struct _proc_stop_obj
{
  int ack_status;
} proc_stop_obj;


typedef struct _src_dest_acl_obj
{
  unsigned int src;
  unsigned int dst;
  unsigned long age;
  unsigned int created_at;
} src_dest_acl_obj;


typedef struct _get_wl_ip_key_obj
{
  unsigned int src;
  unsigned int dst;
} get_wl_ip_key_obj;


typedef struct _del_wl_ip_key_obj
{
  unsigned int src;
  unsigned int dst;
  int status;
} del_wl_ip_key_obj;

typedef struct _get_wl_ip_acl_obj
{
  unsigned int n_acl;
} get_wl_ip_acl_obj;

#endif
