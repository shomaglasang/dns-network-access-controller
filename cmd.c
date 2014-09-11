/*FILE+************************************************************************/
/* Filename    : cmd.c                                                        */
/*                                                                            */
/* Description : Command related routines.                                    */
/*                                                                            */
/* Revisions   : 06/11/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>
#include <dnswldcb.h>
#include <network.h>
#include <cmd.h>


int proc_cmd_status(char *pkt_ptr, int sock, struct sockaddr_in *s_addr)
{
  cmd_hdr *hdr = (cmd_hdr *)pkt_ptr;
  proc_status_obj *obj;
  int ret;

  PUTS_OSYS(LOG_DEBUG, "Processing command status");

  hdr->type = CMD_RESPONSE;

  obj = (proc_status_obj *)(pkt_ptr + sizeof(cmd_hdr));
  obj->pid = (int)getpid();
  obj++;

  sendto(sock, pkt_ptr, ((char *)obj - pkt_ptr), 0,
         (struct sockaddr *)s_addr, sizeof(struct sockaddr_in));

  ret = RET_OK;

  return(ret);
}


int proc_cmd_stop(char *pkt_ptr, int sock, struct sockaddr_in *s_addr)
{
  cmd_hdr *hdr = (cmd_hdr *)pkt_ptr;
  proc_stop_obj *obj;
  int ret;

  PUTS_OSYS(LOG_DEBUG, "Processing command stop");

  hdr->type = CMD_RESPONSE;

  obj = (proc_stop_obj *)(pkt_ptr + sizeof(cmd_hdr));
  obj->ack_status = TRUE;
  obj++;

  sendto(sock, pkt_ptr, ((char *)obj - pkt_ptr), 0,
         (struct sockaddr *)s_addr, sizeof(struct sockaddr_in));

  /****************************************************************************/
  /* Set shutdown flag graceful termination.                                  */
  /****************************************************************************/
  dnswld.proc.is_running = FALSE;

  ret = RET_OK;

  return(ret);
}


int proc_get_wl_ip(char *pkt_ptr, int buf_len, int sock,
                   struct sockaddr_in *s_addr)
{
  cmd_hdr *hdr;
  get_wl_ip_key_obj *key;
  get_wl_ip_acl_obj *wl_obj;
  src_dest_acl_obj *acl_obj;
  src_dest_cb *runner;
  int overrun;
  int idx;
  int ret;

  PUTS_OSYS(LOG_DEBUG, "Processing get whitelist IP");

  hdr = (cmd_hdr *)pkt_ptr;
  hdr++;

  key = (get_wl_ip_key_obj *)hdr;

  if (!key->src)
  {
    idx = 0;
    runner = NULL;
  }
  else
  {
    idx = key->src % ACCESS_LIST_HASH_SIZE;
    PUTS_OSYS(LOG_DEBUG, "idx: [%d]", idx);
    runner = (src_dest_cb *)dnswld.acl.ll.h[idx].head;

    for (; runner; runner = runner->next)
    {
      if (runner->src < key->src)
      {
        break;
      }
      else if ((runner->src == key->src) &&
               (runner->dst == key->dst))
      {
        PUTS_OSYS(LOG_DEBUG, "next src-dst found.");
        runner = runner->next;
        break;
      }
    }

    if (!runner)
    {
      idx++;
    }
  }

  overrun = FALSE;
  hdr = (cmd_hdr *)pkt_ptr;
  hdr->type = CMD_RESPONSE;
  hdr++;

  wl_obj = (get_wl_ip_acl_obj *)hdr;
  wl_obj->n_acl = 0;
  acl_obj = (src_dest_acl_obj *)(wl_obj + 1);

  for (; idx < ACCESS_LIST_HASH_SIZE; idx++)
  {
    if (!runner)
    {
      runner = (src_dest_cb *)dnswld.acl.ll.h[idx].head;
    }

    for (; runner; runner = runner->next)
    {
      acl_obj->src = runner->src;
      acl_obj->dst = runner->dst;
      acl_obj->age = runner->age;
      acl_obj->created_at = (unsigned int)runner->created_at;

      wl_obj->n_acl++;
      acl_obj++;

      if ((((char *)acl_obj - pkt_ptr) + sizeof(src_dest_acl_obj)) > buf_len)
      {
        overrun = TRUE;
        break;
      }
    }

    if (overrun)
    {
      break;
    }
  }

  ret = sendto(sock, pkt_ptr, ((char *)acl_obj - pkt_ptr), 0,
               (struct sockaddr *)s_addr, sizeof(struct sockaddr_in));
  PUTS_OSYS(LOG_DEBUG, " -> n_acl: [%d]", wl_obj->n_acl);
  PUTS_OSYS(LOG_DEBUG, " -> bytes sent: [%d]", ret);

  ret = RET_OK;

  return(ret);
}


int proc_del_wl_ip(char *pkt_ptr, int buf_len, int sock,
                   struct sockaddr_in *s_addr)
{
  cmd_hdr *hdr;
  del_wl_ip_key_obj *key;
  int ret;

  PUTS_OSYS(LOG_DEBUG, "Processing delete whitelist IP");

  hdr = (cmd_hdr *)pkt_ptr;
  key = (del_wl_ip_key_obj *)(hdr + 1);

  PUTS_OSYS(LOG_DEBUG, " Deleting source [%d.%d.%d.%d], dest: [%d.%d.%d.%d]",
                    (key->src >> 24) & 0xFF,
                    (key->src >> 16) & 0xFF,
                    (key->src >> 8) & 0xFF,
                    key->src & 0xFF,
                    (key->dst >> 24) & 0xFF,
                    (key->dst >> 16) & 0xFF,
                    (key->dst >> 8) & 0xFF,
                    key->dst & 0xFF);

  if (!key->src)
  {
    clean_src_dest_whitelist();
    key->status = RET_OK;
  }
  else
  {
    key->status = del_src_dest_whitelist(key->src, key->dst);
  }

  key++;

  hdr->type = CMD_RESPONSE;

  sendto(sock, pkt_ptr, ((char *)key - pkt_ptr), 0,
         (struct sockaddr *)s_addr, sizeof(struct sockaddr_in));

  ret = RET_OK;

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : cmd_reader                                                   */
/*                                                                            */
/* Description : Command channel reader callback.                             */
/*                                                                            */
/* Params      : param (IN)               - Listener info                     */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int cmd_reader(void *param)
{
  listeners_cb *listener = (listeners_cb *)param;
  cmd_hdr *hdr;
  struct sockaddr_in s_addr;
  char *pkt_ptr;
  socklen_t s_size;
  int len;
  int ret;

  /****************************************************************************/
  /* Read command.                                                            */
  /****************************************************************************/
  s_size = sizeof(s_addr);
  pkt_ptr = dnswld.proc.cmd_buf;
  len = recvfrom(listener->sock, pkt_ptr, sizeof(dnswld.proc.cmd_buf),
                 MSG_DONTWAIT, (struct sockaddr*)&s_addr, &s_size);
  PUTS_OSYS(LOG_DEBUG, "Command header len: [%d]", len);
  if (len < sizeof(cmd_hdr))
  {
    PUTS_OSYS(LOG_INFO, "Command header too short: [%d]. Discarding.", len);
    ret = RET_SOCK_READ_ERROR;
    goto EXIT;
  }

  hdr = (cmd_hdr *)dnswld.proc.cmd_buf;

  /****************************************************************************/
  /* Sanitize request.                                                        */
  /****************************************************************************/
  if (hdr->type != CMD_REQUEST)
  {
    PUTS_OSYS(LOG_INFO, "Invalid request type: [%d]. Discarding.", hdr->type);
    ret = RET_INVALID_PARAM;
    goto EXIT;
  }

  /****************************************************************************/
  /* Fan out command.                                                         */
  /****************************************************************************/
  switch (hdr->cmd_id)
  {
    case CMD_STATUS:
      proc_cmd_status(dnswld.proc.cmd_buf, listener->sock, &s_addr);
      break;

    case CMD_STOP:
      proc_cmd_stop(dnswld.proc.cmd_buf, listener->sock, &s_addr);
      break;

    case CMD_GET_WHITELIST_IP:
      proc_get_wl_ip(dnswld.proc.cmd_buf, sizeof(dnswld.proc.cmd_buf),
                     listener->sock, &s_addr);
      break;

    case CMD_DEL_WHITELIST_IP:
      proc_del_wl_ip(dnswld.proc.cmd_buf, sizeof(dnswld.proc.cmd_buf),
                     listener->sock, &s_addr);
      break;

    default:
      PUTS_OSYS(LOG_INFO, "Invalid command ID: [%d]. Discarding.",
                hdr->cmd_id);
      ret = RET_INVALID_PARAM;
      goto EXIT;
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : create_cmd_listener                                          */
/*                                                                            */
/* Description : Create command listener.                                     */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
int create_cmd_listener(void)
{
  int ret;

  ret = create_net_listeners(PF_INET, SOCK_DGRAM, dnswld.proc.cmd_ip,
                             dnswld.proc.cmd_port, cmd_reader);

  return(ret);
}

