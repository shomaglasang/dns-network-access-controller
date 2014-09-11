/*FILE+************************************************************************/
/* Filename    : dnswlctl.c                                                   */
/*                                                                            */
/* Description : DNS whitelist daemon controller.                             */
/*                                                                            */
/* Revisions   : 06/13/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/******************************************************************************/
/* Constants                                                                  */
/******************************************************************************/
#define OBJ_ALL                                   0
#define OBJ_WHITELIST_IP                          1
#define OBJ_WHITELIST_DOMAIN                      2

static char prog_name[51] = {0};
static int cmd_id = CMD_NONE;
static char cmd_kw[51] = {0};
static int opt_all = FALSE;
static int opt_obj = OBJ_WHITELIST_IP;
static int cmd_sock = -1;
static char dest_ip[51] = {0};
static int dest_port = DEF_S_CMD_PORT;
static char acl_src_ip[51] = {0};
static char acl_dst_ip[51] = {0};

typedef struct _cmd_info
{
  char *name;
  int def_cmd_id;
} cmd_info;


typedef struct _response_buf
{
  cmd_hdr hdr;
  union
  {
    proc_status_obj status;
    proc_stop_obj stop;
  } o;
} response_buf;



/*FUNC+************************************************************************/
/* Function    : show_usage                                                   */
/*                                                                            */
/* Description : Show program usage and exit.                                 */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void show_usage(void)
{
  fprintf(stdout, "%s <command> [options]\n", prog_name);
  fprintf(stdout,"Parameters:\n");
  fprintf(stdout,"  command: status|start|stop|show|del\n");
  fprintf(stdout,"  -A: All\n");
  fprintf(stdout,"  -d: Domain\n");
  fprintf(stdout,"  -S <ip>: Source IP\n");
  fprintf(stdout,"  -D <ip>: Destination IP\n");
  fprintf(stdout,"\n");
  exit(0);
}


/*FUNC+************************************************************************/
/* Function    : get_cmd_id                                                   */
/*                                                                            */
/* Description : Get command ID given the command keyword.                    */
/*                                                                            */
/* Params      : argc                     - Number of command line args.      */
/*               argv                     - Arguments array.                  */
/*                                                                            */
/* Returns     : command ID               - On success otherwise -1.          */
/*                                                                            */
/*FUNC-************************************************************************/
static int get_cmd_id(int argc, char **argv)
{
  cmd_info cmds[] = {{"status", CMD_STATUS},
                     {"start", CMD_START},
                     {"stop", CMD_STOP},
                     {"show", CMD_GET_WHITELIST_IP},
                     {"del", CMD_DEL_WHITELIST_IP},
                     {NULL, CMD_NONE}};
  cmd_info *ptr;

  if (argc > 1)
  {
    strncpy(cmd_kw, argv[1], sizeof(cmd_kw) - 1);

    for (ptr = &cmds[0]; ptr->name; ptr++)
    {
      if (!strcasecmp(ptr->name, cmd_kw))
      {
        return(ptr->def_cmd_id);
      }
    }

    return(-1);
  }

  return(CMD_NONE);
}


/*FUNC+************************************************************************/
/* Function    : parse_args                                                   */
/*                                                                            */
/* Description : Parse command line arguments.                                */
/*                                                                            */
/* Params      : argc                     - Number of command line args.      */
/*               argv                     - Arguments array.                  */
/*                                                                            */
/* Returns     : RET_OK                   - Success.                          */
/*               RET_GEN_ERR              - Error.                            */
/*                                                                            */
/*FUNC-************************************************************************/
static int parse_args(int argc, char **argv)
{
  int opt;
  int ret = RET_OK;

  cmd_id = get_cmd_id(argc, argv);
  if (cmd_id < 0)
  {
    fprintf(stdout, "Unknown command: [%s]\n", cmd_kw);
    ret = RET_INVALID_COMMAND;
    goto EXIT;
  }

  if (!cmd_id)
  {
    show_usage();
  }

  optind++;

  while ((opt = getopt(argc, argv, "AdiS:D:")) != -1)
  {
    switch (opt)
    {
      case 'A':
        opt_all = TRUE;
        break;

      case 'i':
        opt_obj = OBJ_WHITELIST_IP;
        break;

      case 'd':
        opt_obj = OBJ_WHITELIST_DOMAIN;
        break;

      case 'S':
        strncpy(acl_src_ip, optarg, sizeof(acl_src_ip) - 1);
        break;

      case 'D':
        strncpy(acl_dst_ip, optarg, sizeof(acl_dst_ip) - 1);
        break;

      default:
        fprintf(stdout, "Invalid option: [%c]\n", opt);
        ret = RET_INVALID_OPTION;
        goto EXIT;
    }
  }

  EXIT:

  return(ret);
}


int create_cmd_socket(void)
{
  struct sockaddr_in c_addr;
  int sock;
  int ret;

  sock = socket(PF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
  {
    return(RET_SOCK_OPEN_ERROR);
  }

  memset(&c_addr, 0, sizeof(c_addr));
  c_addr.sin_family = PF_INET;
  c_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  c_addr.sin_port = htons(DEF_C_CMD_PORT);

  ret = bind(sock, (struct sockaddr*)&c_addr, sizeof(c_addr));
  if (ret < 0)
  {
    close(sock);
    return(-1);
  }

  cmd_sock = sock;
  ret = RET_OK;

  return(ret);
}


void close_cmd_socket(void)
{
  if (cmd_sock >= 0)
  {
    close(cmd_sock);
    cmd_sock = -1;
  }
}


int get_response(int sock, char *buf, int *buf_len)
{
  struct sockaddr_in s_addr;
  struct timeval tval;
  fd_set r_fdset;
  socklen_t s_size;
  int len;
  int ret;

  tval.tv_sec = DEF_CMD_TIMEOUT;
  tval.tv_usec = 0; 

  FD_ZERO(&r_fdset);
  FD_SET(sock, &r_fdset);

  len = select(sock + 1, &r_fdset, NULL, NULL, &tval);
  if ((len > 0) && (FD_ISSET(sock, &r_fdset)))
  {
    s_size = sizeof(s_addr);
    len = recvfrom(sock, buf, *buf_len,
                   MSG_DONTWAIT, (struct sockaddr*)&s_addr, &s_size);
    *buf_len = len;
    ret = RET_OK;
  }
  else
  {
    ret = RET_SOCK_READ_ERROR;
  }

  return(ret);
}


int send_req(char *req, int req_len, char *resp_buf, int *buf_len)
{
  struct sockaddr_in d_addr;
  int len;
  int ret;

  memset(&d_addr, 0, sizeof(d_addr));
  d_addr.sin_family = PF_INET;
  d_addr.sin_addr.s_addr = inet_addr(dest_ip);
  d_addr.sin_port = htons(dest_port);

  len = sendto(cmd_sock, req, req_len, 0,
               (struct sockaddr *)&d_addr, sizeof(struct sockaddr_in));

  if (len != req_len)
  {
    ret = RET_SOCK_WRITE_ERROR;
  }

  if (resp_buf)
  {
    ret = get_response(cmd_sock, resp_buf, buf_len);
    if (ret != RET_OK)
    {
      goto EXIT;
    }
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : get_status                                                   */
/*                                                                            */
/* Description : Get daemon status.                                           */
/*                                                                            */
/* Params      : mute (IN)                - Disable message output.           */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int get_status(int mute)
{
  cmd_hdr cmd;
  response_buf resp_buf;
  int resp_buf_len;
  int ret;

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = CMD_REQUEST;
  cmd.cmd_id = CMD_STATUS;

  resp_buf_len = sizeof(resp_buf);

  ret = send_req((char *)&cmd, sizeof(cmd), (char *)&resp_buf, &resp_buf_len);
  if (ret)
  {
    if (!mute)
    {
      fprintf(stdout, "Daemon is down.\n");
    }

    goto EXIT;
  }
  else
  {
    if (!mute)
    {
      fprintf(stdout, "Daemon is running. PID: [%d]\n", resp_buf.o.status.pid);
    }
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : stop_daemon                                                  */
/*                                                                            */
/* Description : Stop daemon.                                                 */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int stop_daemon(void)
{
  cmd_hdr cmd;
  response_buf resp_buf;
  int resp_buf_len;
  int ret;

  memset(&cmd, 0, sizeof(cmd));
  cmd.type = CMD_REQUEST;
  cmd.cmd_id = CMD_STOP;

  resp_buf_len = sizeof(resp_buf);

  ret = send_req((char *)&cmd, sizeof(cmd), (char *)&resp_buf, &resp_buf_len);
  if (ret)
  {
    fprintf(stdout, "Daemon is down.\n");
    goto EXIT;
  }
  else
  {
    if (resp_buf.o.stop.ack_status)
    {
      fprintf(stdout, "Daemon successfully stopped.\n");
    }
    else
    {
      fprintf(stdout, "Unexpected error in stopping the daemon.\n");
    }
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : start_daemon                                                 */
/*                                                                            */
/* Description : Start daemon.                                                */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int start_daemon(void)
{
  struct stat sb;
  char *path[] = {"/usr/local/sbin",
                  "/usr/sbin",
                  ".",
                  NULL};
  char cmd[155];
  int uid;
  int i;
  int ret;

  /****************************************************************************/
  /* Check permission.                                                        */
  /****************************************************************************/
  uid = getuid();
  if (uid)
  {
    fprintf(stdout, "Change root if fails to start.\n");
  }

  /****************************************************************************/
  /* Check if daemon is running.                                              */
  /****************************************************************************/
  ret = get_status(1);
  if (!ret)
  {
    fprintf(stdout, "Daemon already running.\n");
    goto EXIT;
  }

  close_cmd_socket();

  for (i = 0; path[i]; i++)
  {
    snprintf(cmd, sizeof(cmd), "%s/%s", path[i], CMD_FILENAME);

    ret = stat(cmd, &sb);
    if ((!ret) && (S_ISREG(sb.st_mode)))
    {
      fprintf(stdout, "Starting [%s]\n", cmd);
      ret = system(cmd);
      if (ret)
      {
        fprintf(stdout,"Daemon failed to start.\n");
      }
      else
      {
        fprintf(stdout,"Daemon successfully started.\n");
      }

      break;
    }
  }

  if (!path[i])
  {
    fprintf(stdout, "Program not found!\n");
    ret = RET_FILE_READ_ERROR;
    goto EXIT;
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


int show_whitelist_ip(void)
{
  cmd_hdr *cmd;
  get_wl_ip_key_obj *req;
  get_wl_ip_key_obj next;
  get_wl_ip_acl_obj *wl_obj;
  src_dest_acl_obj *acl_obj;
  time_t cur_time;
  double delta_time;
  char buf[1024];
  char *pbuf = buf;
  char src_ip[15];
  char dst_ip[15];
  char acl_id[15];
  int secs_left;
  int i;
  int ctr = 1;
  int buf_len;
  int more = TRUE;
  int is_first = TRUE;
  int ret;

  memset(&next, 0, sizeof(next));

  while (more)
  {
    cmd = (cmd_hdr *)pbuf;

    memset(cmd, 0, sizeof(cmd_hdr));
    cmd->type = CMD_REQUEST;
    cmd->cmd_id = CMD_GET_WHITELIST_IP;
    cmd++;

    req = (get_wl_ip_key_obj *)cmd;
    *req = next;
    req++;

    buf_len = sizeof(buf);
    ret = send_req((char *)pbuf, ((char *)req - buf), (char *)buf, &buf_len);
    if (ret)
    {
      fprintf(stdout, "Daemon is down.\n");
      break;
    }

    cmd = (cmd_hdr *)buf;
    if ((cmd->type != CMD_RESPONSE) || (cmd->cmd_id != CMD_GET_WHITELIST_IP))
    {
      fprintf(stdout, " Unexpected response. Skipping.\n");
      break;
    }

    cmd++;
    wl_obj = (get_wl_ip_acl_obj *)cmd;

    if (is_first)
    {
      fprintf(stdout, "Whitelisted Source-Destination IP Pair\n");
      fprintf(stdout, "======================================\n");
      fprintf(stdout, "ID  SourceIP   DestinationIP   Seconds Left  Age\n\n");

      if (!wl_obj->n_acl)
      {
        fprintf(stdout, " No whitelisted source-destination IPs.\n");
        break;
      }

      is_first = FALSE;
    }

    if (!wl_obj->n_acl)
    {
      break;
    }

    cur_time = time(NULL);

    acl_obj = (src_dest_acl_obj *)(wl_obj + 1);
    for (i = 0; i < wl_obj->n_acl; i++, acl_obj++, ctr++)
    {
      snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d",
               (acl_obj->src >> 24) & 0xFF,
               (acl_obj->src >> 16) & 0xFF,
               (acl_obj->src >> 8) & 0xFF,
               acl_obj->src & 0xFF);

      snprintf(dst_ip, sizeof(dst_ip), "%d.%d.%d.%d",
               (acl_obj->dst >> 24) & 0xFF,
               (acl_obj->dst >> 16) & 0xFF,
               (acl_obj->dst >> 8) & 0xFF,
               acl_obj->dst & 0xFF);

      snprintf(acl_id, sizeof(acl_id), "[%d]", ctr);

      delta_time = difftime(cur_time, (time_t)acl_obj->created_at);
      secs_left = acl_obj->age - (int)delta_time;

      fprintf(stdout, "%-5s %-16s %-16s %-5d %lu\n",
              acl_id, src_ip, dst_ip, secs_left, acl_obj->age);

      next.src = acl_obj->src;
      next.dst = acl_obj->dst;
    }

    // more = FALSE;
  }

  fprintf(stdout, "\n");

  ret = RET_OK;

  return(ret);
}


int del_whitelist_ip(void)
{
  cmd_hdr *cmd;
  del_wl_ip_key_obj *key;
  in_addr_t addr;
  char buf[1024];
  char *pbuf = buf;
  int buf_len;
  int ret;

  if ((!opt_all) && !(strlen(acl_src_ip)))
  {
    fprintf(stdout, "Source IP or All option not specified.\n");
    ret = RET_INVALID_PARAM;
    goto EXIT;
  }

  cmd = (cmd_hdr *)pbuf;

  memset(cmd, 0, sizeof(cmd_hdr));
  cmd->type = CMD_REQUEST;
  cmd->cmd_id = CMD_DEL_WHITELIST_IP;
  cmd++;

  key = (del_wl_ip_key_obj *)cmd;
  memset(key, 0, sizeof(get_wl_ip_key_obj));

  if (strlen(acl_src_ip))
  {
    addr = inet_addr(acl_src_ip);
    if (addr < 0)
    {
      fprintf(stdout, "Invalid source IP: [%s]\n", acl_src_ip);
      ret = RET_INVALID_PARAM;
      goto EXIT;
    }

    key->src = ntohl(*((unsigned int *)&addr));

    if (strlen(acl_dst_ip))
    {
      addr = inet_addr(acl_dst_ip);
      if (addr < 0)
      {
        fprintf(stdout, "Invalid destination IP: [%s]\n", acl_dst_ip);
        ret = RET_INVALID_PARAM;
        goto EXIT; 
      } 

      key->dst = ntohl(*((unsigned int *)&addr));
    }
  }

  key++;

  buf_len = sizeof(buf);
  ret = send_req((char *)pbuf, ((char *)key - buf), (char *)buf, &buf_len);
  if (ret)
  {
    fprintf(stdout, "Daemon is down.\n");
    goto EXIT;
  }

  cmd = (cmd_hdr *)buf;
  if ((cmd->type != CMD_RESPONSE) || (cmd->cmd_id != CMD_DEL_WHITELIST_IP))
  {
    fprintf(stdout, " Unexpected response. Skipping.\n");
    ret = RET_INVALID_PARAM;
    goto EXIT;
  }

  cmd++;
  key = (del_wl_ip_key_obj *)cmd;
  switch (key->status)
  {
    case RET_OK:
      if (strlen(acl_src_ip))
      {
        fprintf(stdout, "Source-destination whitelist deleted!\n");
      }
      else
      {
        fprintf(stdout, "Deleted ALL whitelisted source-destination pairs.\n");
      }

      break;

    case RET_DATA_NOT_FOUND:
      fprintf(stdout, "Source-destination NOT FOUND!\n");
      break;

    default:
      fprintf(stdout, "Failed to delete source-destination whitelist!\n");
      break;
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : main                                                         */
/*                                                                            */
/* Description : Program's entry point.                                       */
/*                                                                            */
/* Params      : argc                     - Number of command line args.      */
/*               argv                     - Arguments array.                  */
/*                                                                            */
/* Returns     : RET_OK                   - Success.                          */
/*               RET_GEN_ERR              - Error.                            */
/*                                                                            */
/*FUNC-************************************************************************/
int main(int argc, char **argv)
{
  int ret;

  strncpy(prog_name, argv[0], sizeof(prog_name) - 1);
  strcpy(dest_ip, DEF_CMD_IP);

  /****************************************************************************/
  /* Parse command line parameters.                                           */
  /****************************************************************************/
  ret = parse_args(argc, argv);
  if (ret)
  {
    goto EXIT;
  }


  /****************************************************************************/
  /* Create command socket.                                                   */
  /****************************************************************************/
  ret = create_cmd_socket();
  if (ret )
  {
    goto EXIT;
  }

  /****************************************************************************/
  /* Fan out command.                                                         */
  /****************************************************************************/
  switch (cmd_id)
  {
    case CMD_STATUS:
      get_status(0);
      break;

    case CMD_STOP:
      stop_daemon();
      break;

    case CMD_START:
      start_daemon();
      break;

    case CMD_GET_WHITELIST_IP:
      show_whitelist_ip();
      break;

    case CMD_DEL_WHITELIST_IP:
      del_whitelist_ip();
      break;

    default:
      fprintf(stdout, "Unsupported command.\n");
      break;
  }

  ret = RET_OK;

  EXIT:

  close_cmd_socket();

  return(ret);
}

