/*FILE+************************************************************************/
/* Filename    : access_list.c                                                */
/*                                                                            */
/* Description : Access list related routines.                                */
/*                                                                            */
/* Revisions   : 06/04/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>
#include <dnswldcb.h>
#include <fw.h>

#include <sys/socket.h>
#include <netdb.h>

#include <pthread.h>


/******************************************************************************/
/* ACL sweeper pthread ID.                                                    */
/******************************************************************************/
static int is_sweeper_started = FALSE;
static pthread_t sweeper_thread;
static pthread_mutex_t acl_lock = PTHREAD_MUTEX_INITIALIZER;


/*FUNC+************************************************************************/
/* Function    : lock_acl                                                     */
/*                                                                            */
/* Description : Lock ACL from access.                                        */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
static void lock_acl(void)
{
  pthread_mutex_lock(&acl_lock);
}


/*FUNC+************************************************************************/
/* Function    : unlock_acl.                                                  */
/*                                                                            */
/* Description : Unlock ACL from access.                                      */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
static void unlock_acl(void)
{
  pthread_mutex_unlock(&acl_lock);
}


/*FUNC+************************************************************************/
/* Function    : acl_sweeper                                                  */
/*                                                                            */
/* Description : ACL sweeper processing loop.                                 */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void *acl_sweeper(void *param)
{
  llist *acl;
  src_dest_cb *runner;
  src_dest_cb *prev;
  src_dest_cb *tmp;
  time_t cur_time;
  double delta_time;
  int i;

  is_sweeper_started = TRUE;

  PUTS_OSYS(LOG_DEBUG, "ACL sweeper thread: Started");

  while (dnswld.proc.is_running)
  {
    for (i = 0; i < ACCESS_LIST_HASH_SIZE; i++)
    {
      lock_acl();

      acl = &dnswld.acl.ll.h[i];

      for (runner = acl->head, prev = NULL; runner; )
      {
        cur_time = time(NULL);
        delta_time = difftime(cur_time, runner->created_at);
        if (delta_time > (double)runner->age)
        {
          PUTS_OSYS(LOG_DEBUG, " Deleting ACL src: [%d.%d.%d.%d], dst: [%d.%d.%d.%d], age: %f",
                (runner->src >> 24) & 0xFF,
                (runner->src >> 16) & 0xFF,
                (runner->src >> 8) & 0xFF,
                runner->src & 0xFF,
                (runner->dst >> 24) & 0xFF,
                (runner->dst >> 16) & 0xFF,
                (runner->dst >> 8) & 0xFF,
                runner->dst & 0xFF,
                delta_time);

          if (!prev)
          {
            acl->head = runner->next;
          }
          else
          {
            prev->next = runner->next;
          }

          tmp = runner;
          runner = runner->next;
          del_fw_rule(tmp->src, tmp->dst, FW_ACCEPT_RULE, tmp->created_at,
                      tmp->expiry);

          free(tmp);
        }
        else
        {
          prev = runner;
          runner = runner->next;
        }
      }

      unlock_acl();
    }

    sleep(5);
  }

  PUTS_OSYS(LOG_DEBUG, "ACL sweeper thread: Done");

  return(NULL);
}


/*FUNC+************************************************************************/
/* Function    : wait_acl_sweeper                                             */
/*                                                                            */
/* Description : Wait for ACL sweeper to end.                                 */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void wait_acl_sweeper(void)
{
  if (is_sweeper_started)
  {
    pthread_join(sweeper_thread, NULL);
  }
}


/*FUNC+************************************************************************/
/* Function    : create_start_acl_sweeper                                     */
/*                                                                            */
/* Description : Create and start ACL sweeper thread.                         */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int create_start_acl_sweeper(void)
{
  int ret;

  ret = pthread_create(&sweeper_thread, NULL, acl_sweeper, NULL);
  if (ret)
  {
    PUTS_OSYS(LOG_DEBUG, "Failed to create ACL sweeper pthread!");
    ret = RET_SYS_ERROR;
    goto EXIT;
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : add_src_dest_to_whitelist                                    */
/*                                                                            */
/* Description : Add src/dest pair to whitelist and create allow firewall     */
/*               rule.                                                        */
/*                                                                            */
/* Params      : src_addr (IN)            - Source IP.                        */
/*               qs (IN)                  - Array of questions with the       */
/*                                          dest IP.                          */
/*               n_qs (IN)                - Number of questions.              */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int add_src_dest_to_whitelist(void *src_addr, dns_question *qs, int n_qs)
{
  src_dest_cb *sd_cb;
  src_dest_cb *runner;
  src_dest_cb *prev;
  llist *acl;
  dns_question *q;
  unsigned int s_ip;
  unsigned int d_ip;
  in_addr_t addr;
  int found;
  int idx;
  int i;
  int ii;
  int result;
  int ret;

  /****************************************************************************/
  /* Look for A requests.                                                     */
  /****************************************************************************/
  for (i = 0, q = qs; i < n_qs; i++, q++)
  {
    if ((q->q_type != DNS_RR_TYPE_A) || (q->q_class != DNS_RR_CLASS_IN))
    {
      continue;
    }

    for (ii = 0; ii < q->ans.n_rec; ii++)
    {
      found = FALSE;

      /************************************************************************/
      /* Convert to int for better handling. Needs further enhancements.      */
      /************************************************************************/
      s_ip = ntohl(*((unsigned int *)(&((struct sockaddr_in*)src_addr)->sin_addr)));
      addr = inet_addr(q->ans.recs[ii]);
      d_ip = ntohl(*((unsigned int *)&addr));

      PUTS_OSYS(LOG_DEBUG, " Adding src_ip: [%d.%d.%d.%d], dst_ip: [%d.%d.%d.%d]",
                (s_ip >> 24) & 0xFF,
                (s_ip >> 16) & 0xFF,
                (s_ip >> 8) & 0xFF,
                s_ip & 0xFF,
                (d_ip >> 24) & 0xFF,
                (d_ip >> 16) & 0xFF,
                (d_ip >> 8) & 0xFF,
                d_ip & 0xFF);

      sd_cb = (src_dest_cb *)malloc(sizeof(src_dest_cb));
      if (!sd_cb)
      {
        PUTS_OSYS(LOG_DEBUG, " Failed to allocate memory for src-dest cb");
        ret = RET_MEMORY_ERROR;
        goto EXIT;
      }

      memset(sd_cb, 0, sizeof(src_dest_cb));
      sd_cb->src = s_ip;
      sd_cb->dst = d_ip;
      sd_cb->age = dnswld.proc.wl_age;
      sd_cb->created_at = time(NULL);
      sd_cb->expiry = sd_cb->created_at + dnswld.proc.wl_age;

      idx = s_ip % ACCESS_LIST_HASH_SIZE;

      lock_acl();

      acl = &dnswld.acl.ll.h[idx];

      PUTS_OSYS(LOG_DEBUG, " idx: [%d]", idx);

      /************************************************************************/
      /* Insert ACL entry to the list.                                        */
      /************************************************************************/
      if (acl->head)
      {
        for (runner = acl->head, prev = NULL; runner;
             prev = runner, runner = runner->next)
        {
          result = 1;
          if (s_ip < runner->src)
          {
            result = -1;
            break;
          }
          else if (s_ip == runner->src)
          {
            result = 0;
            if (d_ip == runner->dst)
            {
              break;
            }
          }
        }

        if ((!result) && (runner) && (d_ip == runner->dst))
        {
          runner->ref_count++;
          PUTS_OSYS(LOG_DEBUG, "  Found existing acl entry. Ref count: %d",
                    runner->ref_count);
          found = TRUE;
        }
        else if (!prev)
        {
          PUTS_OSYS(LOG_DEBUG, " Adding before [%d.%d.%d.%d], dst_ip: [%d.%d.%d.%d]",
                    (runner->src >> 24) & 0xFF,
                    (runner->src >> 16) & 0xFF,
                    (runner->src >> 8) & 0xFF,
                     runner->src & 0xFF,
                    (runner->dst >> 24) & 0xFF,
                    (runner->dst >> 16) & 0xFF,
                    (runner->dst >> 8) & 0xFF,
                     runner->dst & 0xFF);

          sd_cb->next = runner;
          acl->head = sd_cb;
        }
        else
        {
          PUTS_OSYS(LOG_DEBUG, " Adding after [%d.%d.%d.%d], dst_ip: [%d.%d.%d.%d]",
                    (prev->src >> 24) & 0xFF,
                    (prev->src >> 16) & 0xFF,
                    (prev->src >> 8) & 0xFF,
                    prev->src & 0xFF,
                    (prev->dst >> 24) & 0xFF,
                    (prev->dst >> 16) & 0xFF,
                    (prev->dst >> 8) & 0xFF,
                    prev->dst & 0xFF);

          ((src_dest_cb *)prev)->next = sd_cb;
        }
      }
      else
      {
        PUTS_OSYS(LOG_DEBUG, " Adding first entry");
        acl->head = sd_cb;
      }

      if (((!found) && (!dnswld.proc.disable_fw)) ||
          ((found) && (runner->last_status == ACL_ADD_ALLOW_RULE_ERR)))
      {
        PUTS_OSYS(LOG_DEBUG, " Adding FW Pass rule");
        /**********************************************************************/
        /* Add allow firewall rule for src and dest.                          */
        /**********************************************************************/
        ret = add_fw_rule(s_ip, d_ip, FW_ACCEPT_RULE, sd_cb->created_at,
                          sd_cb->expiry);
        if (ret)
        {
          PUTS_OSYS(LOG_CRIT, " Error adding FW Pass rule. Marking ACL entry");
          if (found)
          {
            runner->last_status = ACL_ADD_ALLOW_RULE_ERR;
          }
          else
          {
            sd_cb->last_status = ACL_ADD_ALLOW_RULE_ERR;
          }
        }
      }

      unlock_acl();

      if (found)
      {
        free(sd_cb);
      }
    }
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : del_src_dest_whitelist                                       */
/*                                                                            */
/* Description : Delete source-destination whitelist.                         */
/*                                                                            */
/* Params      : src (IN)                 - Source IP.                        */
/*               dst (IN)                 - Destination IP.                   */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int del_src_dest_whitelist(unsigned int src, unsigned int dst)
{
  src_dest_cb *runner;
  src_dest_cb *prev;
  src_dest_cb *tmp;
  llist *acl;
  int is_match;
  int idx;
  int ret = RET_DATA_NOT_FOUND;

  idx = src % ACCESS_LIST_HASH_SIZE;

  lock_acl();

  acl = &dnswld.acl.ll.h[idx];

  for (runner = acl->head, prev = NULL; runner; )
  {
    is_match = FALSE;
    if (src == runner->src)
    {
      if (dst)
      {
        if (dst == runner->dst)
        {
          is_match = TRUE;
        }
      }
      else
      {
        is_match = TRUE;
      }
    }
    else if (src > runner->src)
    {
      break;
    }

    if (is_match)
    {
      PUTS_OSYS(LOG_DEBUG, " ACL found.");

      if (!prev)
      {
        acl->head = runner->next;
      }
      else
      {
        prev->next = runner->next;
      }

      tmp = runner;
      runner = runner->next;
      del_fw_rule(tmp->src, tmp->dst, FW_ACCEPT_RULE, tmp->created_at,
                  tmp->expiry);

      free(tmp);

      ret = RET_OK;

      if (dst)
      {
        break;
      }
    }
    else
    {
      prev = runner;
      runner = runner->next;
    }
  }

  unlock_acl();

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : clean_src_dest_whitelist                                     */
/*                                                                            */
/* Description : Clean source-destination whitelist.                          */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void clean_src_dest_whitelist(void)
{
  src_dest_cb *runner;
  src_dest_cb *prev;
  llist *acl;
  int i;

  lock_acl();

  for (i = 0; i < ACCESS_LIST_HASH_SIZE; i++)
  {
    acl = &dnswld.acl.ll.h[i];

    for (runner = acl->head; runner; )
    {
      prev = runner;
      runner = runner->next;

      del_fw_rule(prev->src, prev->dst, FW_ACCEPT_RULE, prev->created_at,
                  prev->expiry);
      free(prev);
    }
  }

  unlock_acl();
}


/*FUNC+************************************************************************/
/* Function    : create_whitelist_from_fw_rules                               */
/*                                                                            */
/* Description : Create whitelist from existing firewall rules.               */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int create_whitelist_from_fw_rules(void)
{
  src_dest_cb *sd_cb;
  src_dest_cb *runner;
  src_dest_cb *prev;
  llist *acl;
  FILE *in = NULL;
  char cmd[1024];
  char *line;
  char *token;
  char *saveptr;
  char src[IP4_STR_MAX_LEN];
  char dest[IP4_STR_MAX_LEN];
  unsigned int s_ip;
  unsigned int d_ip;
  in_addr_t addr;
  time_t created_time;
  time_t cur_time;
  double delta_time;
  int found;
  int result;
  int idx;
  int i;
  int ret;

  PUTS_OSYS(LOG_DEBUG, "Re-creating whitelist from firewall rules.");

  /****************************************************************************/
  /* Dump whitelist firewall rules.                                           */
  /****************************************************************************/
  snprintf(cmd, sizeof(cmd), "%s -n -L | grep %s > %s",
           dnswld.fw.iptables_path, FW_RULE_TAG, DNSWLD_FW_DUMP);

  PUTS_OSYS(LOG_DEBUG, " cmd: [%s]", cmd);
  ret = system(cmd);
  if (ret < 0)
  {
    PUTS_OSYS(LOG_DEBUG, "Error dumping whitelist firewall rules.");
    ret = RET_SYS_ERROR;
    goto EXIT;
  }

  /****************************************************************************/
  /* Parse the dump file and extract ACL information to build the whitelist.  */
  /****************************************************************************/
  in = fopen(DNSWLD_FW_DUMP, "r");
  if (!in)
  {
    PUTS_OSYS(LOG_ERR, "Failed to whitelist firewall rules dump file [%s].",
              DNSWLD_FW_DUMP);
    ret = RET_FILE_OPEN_ERROR;
    goto EXIT;
  }

  while ((line = fgets(cmd, sizeof(cmd), in)))
  {
    trim_str(line);
    PUTS_OSYS(LOG_DEBUG, " line: [%s]", cmd);

    for (token = strtok_r(line, " ", &saveptr), i = 0; token != NULL;
         token = strtok_r(NULL, " ", &saveptr), i++)
    {
      switch (i)
      {
        case 3:
          strncpy(src, token, sizeof(src) - 1);
          break;

        case 4:
          strncpy(dest, token, sizeof(dest) - 1);
          break;

        case 8:
          *((unsigned int *)&created_time) = (unsigned int)strtoul(token, NULL, 10);
          break;
      }
    }

    PUTS_OSYS(LOG_DEBUG, " src:    [%s]", src);
    PUTS_OSYS(LOG_DEBUG, " dest:   [%s]", dest);
    PUTS_OSYS(LOG_DEBUG, " created_time: [%u]", created_time);

    addr = inet_addr(src);
    s_ip = ntohl(*((unsigned int *)&addr));
    addr = inet_addr(dest);
    d_ip = ntohl(*((unsigned int *)&addr));

    cur_time = time(NULL);
    delta_time = difftime(created_time + dnswld.proc.wl_age, cur_time);
    if (delta_time <= 0)
    {
      PUTS_OSYS(LOG_DEBUG, " Whitelist firewall already expired. Deleting ...");
      del_fw_rule(s_ip, d_ip, FW_ACCEPT_RULE, created_time,
                  created_time + dnswld.proc.wl_age);
      continue;
    }

    PUTS_OSYS(LOG_DEBUG, " Adding src_ip: [%d.%d.%d.%d], dst_ip: [%d.%d.%d.%d], "
              "age: [%f]",
              (s_ip >> 24) & 0xFF,
              (s_ip >> 16) & 0xFF,
              (s_ip >> 8) & 0xFF,
              s_ip & 0xFF,
              (d_ip >> 24) & 0xFF,
              (d_ip >> 16) & 0xFF,
              (d_ip >> 8) & 0xFF,
              d_ip & 0xFF,
              delta_time);

    sd_cb = (src_dest_cb *)malloc(sizeof(src_dest_cb));
    if (!sd_cb)
    {
      PUTS_OSYS(LOG_DEBUG, " Failed to allocate memory for src-dest cb");
      ret = RET_MEMORY_ERROR;
      goto EXIT;
    }

    memset(sd_cb, 0, sizeof(src_dest_cb));
    sd_cb->src = s_ip;
    sd_cb->dst = d_ip;
    sd_cb->age = dnswld.proc.wl_age;
    sd_cb->created_at = created_time;
    sd_cb->expiry = created_time + dnswld.proc.wl_age;

    idx = s_ip % ACCESS_LIST_HASH_SIZE;

    acl = &dnswld.acl.ll.h[idx];

    PUTS_OSYS(LOG_DEBUG, " idx: [%d]", idx);

    found = FALSE;

    /**************************************************************************/
    /* Insert ACL entry to the list.                                          */
    /**************************************************************************/
    if (acl->head)
    {
      for (runner = acl->head, prev = NULL; runner;
           prev = runner, runner = runner->next)
      {
        result = 1;
        if (s_ip < runner->src)
        {
          result = -1;
          break;
        }
        else if (s_ip == runner->src)
        {
          result = 0;
          if (d_ip == runner->dst)
          {
            break;
          }
        }
      }

      if ((!result) && (runner) && (d_ip == runner->dst))
      {
        runner->ref_count++;
        PUTS_OSYS(LOG_DEBUG, "  Found existing acl entry. Ref count: %d",
                  runner->ref_count);
        found = TRUE;
      }
      else if (!prev)
      {
        PUTS_OSYS(LOG_DEBUG, " Adding before [%d.%d.%d.%d], dst_ip: [%d.%d.%d.%d]",
                  (runner->src >> 24) & 0xFF,
                  (runner->src >> 16) & 0xFF,
                  (runner->src >> 8) & 0xFF,
                  runner->src & 0xFF,
                  (runner->dst >> 24) & 0xFF,
                  (runner->dst >> 16) & 0xFF,
                  (runner->dst >> 8) & 0xFF,
                  runner->dst & 0xFF);

        sd_cb->next = runner;
        acl->head = sd_cb;
      }
      else
      {
        PUTS_OSYS(LOG_DEBUG, " Adding after [%d.%d.%d.%d], dst_ip: [%d.%d.%d.%d]",
                  (prev->src >> 24) & 0xFF,
                  (prev->src >> 16) & 0xFF,
                  (prev->src >> 8) & 0xFF,
                  prev->src & 0xFF,
                  (prev->dst >> 24) & 0xFF,
                  (prev->dst >> 16) & 0xFF,
                  (prev->dst >> 8) & 0xFF,
                  prev->dst & 0xFF);

        ((src_dest_cb *)prev)->next = sd_cb;
      }
    }
    else
    {
      PUTS_OSYS(LOG_DEBUG, " Adding first entry");
      acl->head = sd_cb;
    }

    if (found)
    {
      free(sd_cb);
    }
  }

  ret = RET_OK;

  EXIT:

  if (in)
  {
    fclose(in);
  }

  return(ret);
}

