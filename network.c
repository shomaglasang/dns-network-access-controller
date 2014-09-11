/*FILE+************************************************************************/
/* Filename    : network.c                                                    */
/*                                                                            */
/* Description : Network related routines.                                    */
/*                                                                            */
/* Revisions   : 05/12/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>

#include <sys/socket.h>
#include <netdb.h>

#include <dnswldcb.h>
#include <response.h>


/*FUNC+************************************************************************/
/* Function    : dump_dns_header                                              */
/*                                                                            */
/* Description : Dump DNS header.                                             */
/*                                                                            */
/* Params      : dns_hdr (IN)             - DNS header.                       */
/*               s_addr (IN)              - Source IP address                 */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
static void dump_dns_header(dns_header *dns_hdr, struct sockaddr_in *s_addr)
{
  char addr_str[IP4_STR_MAX_LEN];
  char port_str[PORT_STR_MAX_LEN];
  int ret;

  ret = getnameinfo((struct sockaddr *)s_addr,
                    sizeof(struct sockaddr_in), addr_str,
                    sizeof(addr_str), port_str, sizeof(port_str),
                    NI_NUMERICHOST | NI_NUMERICSERV);
  if (ret)
  {
    PUTS_OSYS(LOG_DEBUG, " Error translating sockets info.");
  }
  else
  {
    PUTS_OSYS(LOG_DEBUG, " DNS Request received from: [%s] [%s]",
              addr_str, port_str);
    PUTS_OSYS(LOG_DEBUG, "- DNS HDR id: [%X]", dns_hdr->id);
    PUTS_OSYS(LOG_DEBUG, "  DNS HDR flags/codes: [%X]", dns_hdr->fc);
    PUTS_OSYS(LOG_DEBUG, "  DNS HDR qd_count: [%d]", dns_hdr->q_count);
    PUTS_OSYS(LOG_DEBUG, "  DNS HDR an_count: [%d]", dns_hdr->ans_count);
    PUTS_OSYS(LOG_DEBUG, "  DNS HDR ns_count: [%d]", dns_hdr->ns_count);
    PUTS_OSYS(LOG_DEBUG, "  DNS HDR ar_count: [%d]", dns_hdr->addrec_count);
  }
}


/*FUNC+************************************************************************/
/* Function    : dump_dns_question                                            */
/*                                                                            */
/* Description : Dump DNS question.                                           */
/*                                                                            */
/* Params      : q (IN)                   - DNS question.                     */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void dump_dns_question(dns_question *q)
{
  char name[DNS_MAX_NAME_LEN];
  int i;

  memset(name, 0, sizeof(name));
  PUTS_OSYS(LOG_DEBUG, "Question:");
  PUTS_OSYS(LOG_DEBUG, " Type : %d", q->q_type);
  PUTS_OSYS(LOG_DEBUG, " Class: %d", q->q_class);

  for (i = 0; i < q->n_label; i++)
  {
    if (i)
    {
      snprintf(&name[strlen(name)], sizeof(name) - strlen(name), ".%s",
               q->labels[i]);
    }
    else
    {
      snprintf(&name[strlen(name)], sizeof(name) - strlen(name), "%s",
               q->labels[i]);
    }
  }

  PUTS_OSYS(LOG_DEBUG, " Name: [%s]", name);
}


/*FUNC+************************************************************************/
/* Function    : dump_dns_questions                                           */
/*                                                                            */
/* Description : Dump DNS questions.                                          */
/*                                                                            */
/* Params      : qs (IN)                  - DNS questions.                    */
/* Params      : n (IN)                   - Number of questions.              */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void dump_dns_questions(dns_question *qs, int n)
{
  int i;

  PUTS_OSYS(LOG_DEBUG, "= Questions =");

  for (i = 0; i < n; i++)
  {
    dump_dns_question(&qs[i]);
  }
}


/*FUNC+************************************************************************/
/* Function    : parse_question_section                                       */
/*                                                                            */
/* Description : Parse DNS question section.                                  */
/*                                                                            */
/* Params      : pkt (IN/OUT)             - Points to sections in DNS query.  */
/*               pkt_len (IN)             - Len of DNS query packet.          */
/*               dns_questions (OUT)      - Placeholder of parsed question.   */
/*               n_q (IN)                 - Number of placeholders.           */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int parse_question_section(char **pkt, int pkt_len, dns_question *questions,
                           int n_q)
{
  dns_question *q_ptr;
  char *pkt_ptr = *pkt;
  char label_len;
  int i;
  int i_label;
  int ret;

  PUTS_OSYS(LOG_DEBUG, "pkt_len: [%d]", pkt_len);

  /****************************************************************************/
  /* Parse entries in question section.                                       */
  /****************************************************************************/
  for (i = 0; i < n_q; i++)
  {
    q_ptr = &questions[i];
    memset(q_ptr, 0, sizeof(*q_ptr));

    for (i_label = 0; ; i_label++)
    {
      /************************************************************************/
      /* There needs to be at least 4 bytes left for question type and code.  */
      /************************************************************************/
      if (pkt_len <= 4)
      {
        PUTS_OSYS(LOG_DEBUG,
                  "Malformed DNS request. Question section too short: [%d]",
                  pkt_len);
        ret = RET_MALFORMED_DNS_REQ;
        goto EXIT;
      }

      /************************************************************************/
      /* Get label length and sanitize.                                       */
      /************************************************************************/
      label_len = *pkt_ptr++;
      pkt_len--;

      PUTS_OSYS(LOG_DEBUG, "-> label_len[%d]: [%d]", i_label, label_len);

      if (label_len == 0)
      {
        break;
      }

      if (label_len > DNS_MAX_LABEL_LEN)
      {
        PUTS_OSYS(LOG_DEBUG, "Malformed DNS request. "
                  "Label length too long: [%d]", label_len);
        ret = RET_MALFORMED_DNS_REQ;
        goto EXIT;
      }

      if (label_len >= pkt_len)
      {
        PUTS_OSYS(LOG_DEBUG, "Malformed DNS request. "
                  "Label octets too short: [%d]", label_len);
        ret = RET_MALFORMED_DNS_REQ;
        goto EXIT;
      }

      /************************************************************************/
      /* Get label octets.                                                    */
      /************************************************************************/
      memcpy(&q_ptr->labels[i_label], pkt_ptr, label_len);

      PUTS_OSYS(LOG_DEBUG, "-> label[%d]: [%s]", i_label,
                q_ptr->labels[i_label]);

      if (i_label)
      {
        snprintf(&q_ptr->name[strlen(q_ptr->name)],
                 (sizeof(q_ptr->name) - strlen(q_ptr->name)), ".%s",
                 q_ptr->labels[i_label]);
      }
      else
      {
        snprintf(&q_ptr->name[strlen(q_ptr->name)],
                 (sizeof(q_ptr->name) - strlen(q_ptr->name)), "%s",
                 q_ptr->labels[i_label]);
      }

      pkt_ptr += label_len;
      pkt_len -= label_len;
    }

    q_ptr->n_label = i_label;

    q_ptr->q_type = ntohs(*(unsigned short *)pkt_ptr);
    pkt_ptr += sizeof(unsigned short);
    pkt_len -= sizeof(unsigned short);
    q_ptr->q_class = ntohs(*(unsigned short *)pkt_ptr);
    pkt_ptr += sizeof(unsigned short);
    pkt_len -= sizeof(unsigned short);

    PUTS_OSYS(LOG_DEBUG, "-> q_type: [%d]", q_ptr->q_type);
    PUTS_OSYS(LOG_DEBUG, "-> q_class: [%d]", q_ptr->q_class);
  }

  *pkt = pkt_ptr;
  ret = RET_OK;

  EXIT:

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : dns_sock_reader                                              */
/*                                                                            */
/* Description : DNS socket reader.                                           */
/*                                                                            */
/* Params      : param (IN)               - Listener info                     */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int dns_sock_reader(void *param)
{
  listeners_cb *listener = (listeners_cb *)param;
  dns_header *dns_hdr;
  struct sockaddr_in s_addr;
  dns_question *questions = NULL;
  char *pkt_ptr;
  socklen_t s_size;
  int len;
  int ret;

  /****************************************************************************/
  /* Read DNS query.                                                          */
  /****************************************************************************/
  s_size = sizeof(s_addr);
  pkt_ptr = dnswld.proc.pkt_buf;
  len = recvfrom(listener->sock, pkt_ptr, dnswld.proc.pkt_bufz,
                 MSG_DONTWAIT, (struct sockaddr*)&s_addr, &s_size);
  PUTS_OSYS(LOG_DEBUG, "DNS request len: [%d]", len);
  if (len < sizeof(dns_header))
  {
    PUTS_OSYS(LOG_DEBUG, "DNS request too short: [%d]. Discarding.", len);
    ret = RET_SOCK_READ_ERROR;
    goto EXIT;
  }

  dns_hdr = (dns_header *)dnswld.proc.pkt_buf;

  dns_hdr->id = ntohs(dns_hdr->id);
  dns_hdr->fc = ntohs(dns_hdr->fc);
  dns_hdr->q_count = ntohs(dns_hdr->q_count);
  dns_hdr->ans_count = ntohs(dns_hdr->ans_count);
  dns_hdr->ns_count = ntohs(dns_hdr->ns_count);
  dns_hdr->addrec_count = ntohs(dns_hdr->addrec_count);

  if (dnswld.log.is_debug_on)
  {
    dump_dns_header(dns_hdr, &s_addr);
  }

  /****************************************************************************/
  /* Query must have at least one question.                                   */
  /****************************************************************************/
  if (dns_hdr->q_count <= 0)
  {
    PUTS_OSYS(LOG_DEBUG, "Malformed DNS header. Invalid question count.");
    ret = RET_MALFORMED_DNS_REQ;
    goto EXIT;
  }

  pkt_ptr += sizeof(*dns_hdr);
  len -= sizeof(*dns_hdr);

  if (!len)
  {
    PUTS_OSYS(LOG_DEBUG, "Malformed DNS request. Missing question section.");
    ret = RET_MALFORMED_DNS_REQ;
    goto EXIT;
  }

  /****************************************************************************/
  /* Read questions.                                                          */
  /****************************************************************************/
  questions = (dns_question*)malloc(sizeof(dns_question) * dns_hdr->q_count);
  if (questions == NULL)
  {
    PUTS_OSYS(LOG_DEBUG, "Failed to allocate memory for questions.");
    ret = RET_MEMORY_ERROR;
    goto EXIT;
  }

  ret = parse_question_section(&pkt_ptr, len, questions, dns_hdr->q_count);
  if (ret)
  {
    goto EXIT;
  }

  dump_dns_questions(questions, dns_hdr->q_count);

  /****************************************************************************/
  /* Process requested domains.                                               */
  /****************************************************************************/
  ret = process_requested_domains(&s_addr, questions, dns_hdr->q_count);
  if (!ret)
  {
    /**************************************************************************/
    /* Send response.                                                         */
    /**************************************************************************/
    process_response(listener, &s_addr, pkt_ptr, dns_hdr, questions);
  }

  EXIT:

  if (ret)
  {
    if (questions)
    {
      free(questions);
    }
  }

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : create_udp_listener                                          */
/*                                                                            */
/* Description : Create UDP listener.                                         */
/*                                                                            */
/* Params      : fam (IN)                 - Protocal family                   */
/*               ip (IN)                  - IP address                        */
/*               port (IN)                - Port                              */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
static int create_udp_listener(int fam, char *ip, int port)
{
  struct sockaddr_in s_addr;
  int sock;
  int ret;

  sock = socket(fam, SOCK_DGRAM, 0);
  if (sock < 0)
  {
    return(-1);
  }

  memset(&s_addr, 0, sizeof(s_addr));
  s_addr.sin_family = fam;
  s_addr.sin_addr.s_addr = inet_addr(ip);
  if (port > 0)
  {
    s_addr.sin_port = htons(port);
  }

  ret = bind(sock, (struct sockaddr*)&s_addr, sizeof(s_addr));
  if (ret < 0)
  {
    close(sock);
    return(-1);
  }

  return(sock);
}


/*FUNC+************************************************************************/
/* Function    : create_net_listeners                                         */
/*                                                                            */
/* Description : Create network or socket listener.                           */
/*                                                                            */
/* Params      : fam (IN)                 - Protocol family.                  */
/*               type (IN)                - Socket type.                      */
/*               ip (IN)                  - IP address in string format.      */
/*               port (IN)                - Port.                             */
/*               sock_reader (IN)         - Socket reader callback.           */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int create_net_listeners(int fam, int type, char *ip, int port,
                         SOCK_READER sock_reader)
{
  listeners_cb *listener = NULL;
  int sock;
  int ret;

  if (type == SOCK_DGRAM)
  {
    sock = create_udp_listener(fam, ip, port);
  }
  else
  {
    sock = 0;
    ret = RET_SOCK_OPEN_ERROR;
    goto EXIT;
  }

  if (sock < 0)
  {
    PUTS_OSYS(LOG_ERR, "Error creating network listener: [%d %s:%d]",
              type, ip, port);
    ret = RET_SOCK_OPEN_ERROR;
    goto EXIT;
  }

  listener = (listeners_cb *)malloc(sizeof(listeners_cb));
  if (!listener)
  {
    PUTS_OSYS(LOG_ERR, "Network listener malloc error.");
    ret = RET_MEMORY_ERROR;
    goto EXIT;
  }

  memset(listener, 0, sizeof(listeners_cb));
  listener->sock = sock;
  listener->port = port;
  strncpy(listener->addr4_str, ip, sizeof(listener->addr4_str) - 1);

  listener->sock_reader = sock_reader;

  llist_add((llist *)&dnswld.listeners, (llitem *)listener);

  PUTS_OSYS(LOG_DEBUG, "Network listener socket: [%d].", listener->sock);

  ret = RET_OK;

  EXIT:

  if (ret)
  {
    if (sock >= 0)
    {
      close(sock);
    }

    if (listener)
    {
      free(listener);
    }
  }

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : create_def_listeners                                         */
/*                                                                            */
/* Description : Create default listener.                                     */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int create_def_listeners(void)
{
  listeners_cb *listener = NULL;
  int sock;
  int ret;

  sock = create_udp_listener(PF_INET, DEF_DNSWLD_IP4, DEF_DNSWLD_PORT);
  if (sock < 0)
  {
    PUTS_OSYS(LOG_ERR, "Error creating UDP listener: [%s:%d]",
              DEF_DNSWLD_IP4, DEF_DNSWLD_PORT);
    ret = RET_SOCK_OPEN_ERROR;
    goto EXIT;
  }

  listener = (listeners_cb *)malloc(sizeof(listeners_cb));
  if (!listener)
  {
    PUTS_OSYS(LOG_ERR, "UDP listener malloc error.");
    ret = RET_MEMORY_ERROR;
    goto EXIT;
  }

  memset(listener, 0, sizeof(listeners_cb));
  listener->sock = sock;
  listener->port = DEF_DNSWLD_PORT;
  strncpy(listener->addr4_str, DEF_DNSWLD_IP4, sizeof(listener->addr4_str) - 1);

  listener->sock_reader = dns_sock_reader;

  llist_add((llist *)&dnswld.listeners, (llitem *)listener);

  PUTS_OSYS(LOG_DEBUG, "Default listener socket: [%d].", listener->sock);

  ret = RET_OK;

  EXIT:

  if (ret)
  {
    if (sock >= 0)
    {
      close(sock);
    }

    if (listener)
    {
      free(listener);
    }
  }

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : create_listeners                                             */
/*                                                                            */
/* Description : Create listeners.                                            */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int create_listeners(void)
{
  int ret;

  if (dnswld.listeners.head)
  {
  }
  else
  {
    ret = create_def_listeners();
  }

  return(ret);
}


/*FUNC+************************************************************************/
/* Function    : clean_listeners                                              */
/*                                                                            */
/* Description : Clean listeners.                                             */
/*                                                                            */
/* Params      : none                                                         */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void clean_listeners(void)
{
  listeners_cb *runner;

  if (dnswld.listeners.head)
  {
    runner = dnswld.listeners.head;
    while (runner)
    {
      if (runner->sock >= 0)
      {
        PUTS_OSYS(LOG_DEBUG, "Closing socket: [%d].", runner->sock);
        close(runner->sock);
      }

      runner = runner->next;
    }

    llist_clean((llist *)&dnswld.listeners);
  }
}


/*FUNC+************************************************************************/
/* Function    : map_listeners_fdset                                          */
/*                                                                            */
/* Description : Map listener sockets to fdset.                               */
/*                                                                            */
/* Params      : fdset_ptr (OUT)          - Listener fdset                    */
/*                                                                            */
/* Returns     : nfds                     - Highest numbered socket.          */
/*                                                                            */
/*FUNC-************************************************************************/
int map_listeners_fdset(void *ptr)
{
  fd_set r_fdset;
  listeners_cb *runner = dnswld.listeners.head;
  int nfds = 0;

  FD_ZERO(&r_fdset);

  while (runner)
  {
    if (runner->sock >= 0)
    {
      FD_SET(runner->sock, &r_fdset);

      if (runner->sock > nfds)
      {
        nfds = runner->sock;
      }
    }

    runner = runner->next;
  }

  *((fd_set *)ptr) = r_fdset;

  return(nfds);
}


/*FUNC+************************************************************************/
/* Function    : check_listeners                                              */
/*                                                                            */
/* Description : Chekc if listeners has incoming connections.                 */
/*                                                                            */
/* Params      : ptr (IN)                 - Read fdset                        */
/*               nfds (IN)                - Highest numbered socket in fdset  */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void check_listeners(void *ptr, int nfds)
{
  struct timeval tval;
  fd_set r_fdset = *((fd_set *)ptr);
  listeners_cb *runner = dnswld.listeners.head;
  int nset;

  nfds++;

  tval.tv_sec  = 1;
  tval.tv_usec = 0;

  nset = select(nfds, &r_fdset, NULL, NULL, &tval);
  if (nset <= 0)
  {
    return;
  }

  while (runner)
  {
    if ((runner->sock >= 0) && (FD_ISSET(runner->sock, &r_fdset)))
    {
      PUTS_OSYS(LOG_DEBUG, "data ready on listener socket: [%d]",
                runner->sock);
      runner->sock_reader(runner);
    }

    runner = runner->next;
  }
}

