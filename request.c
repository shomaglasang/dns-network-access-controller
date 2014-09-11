/*FILE+************************************************************************/
/* Filename    : request.c                                                    */
/*                                                                            */
/* Description : Routines to process requested domains.                       */
/*                                                                            */
/* Revisions   : 05/23/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>
#include <dnswldcb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


/*FUNC+************************************************************************/
/* Function    : process_requested_domains                                    */
/*                                                                            */
/* Description : Process requested domains.                                   */
/*                                                                            */
/* Params      : src_addr (IN)            - Source IP address                 */
/*               qs (IN)                  - Array of questions.               */
/*               n_qs (IN)                - Number of questions.              */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int process_requested_domains(void *src_addr, dns_question *qs, int n_qs)
{
  struct addrinfo hints;
  struct addrinfo *res0 = NULL;
  struct addrinfo *res;
  dns_question *q;
  int i_rec;
  int i;
  int ret;

  /****************************************************************************/
  /* Look for A requests.                                                     */
  /****************************************************************************/
  for (i = 0, q = qs; i < n_qs; i++, q++)
  {
    if ((q->q_type == DNS_RR_TYPE_A) && (q->q_class == DNS_RR_CLASS_IN))
    {
      /************************************************************************/
      /* Check if name is included in whitelist.                              */
      /************************************************************************/
      if (find_name(q, dnswld.ds.whitelist))
      {
        PUTS_OSYS(LOG_DEBUG, "[%s] found in whitelist! Resolving ...",
                  q->name);

        /**********************************************************************/
        /* Resolve address of name. We're interested for IPv4 for now.        */
        /**********************************************************************/
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_CANONNAME;

        ret = getaddrinfo(q->name, NULL, &hints, &res0);
        if (ret != 0)
        {
          PUTS_OSYS(LOG_ERR, " Failed to resolve name!");
          continue;
        }

        /**********************************************************************/
        /* Get returned address.                                              */
        /**********************************************************************/
        for (i_rec = 0, res = res0; res && i_rec < DNS_MAX_ANS_RR_NUM;
             res = res->ai_next)
        {
          ret = getnameinfo(res->ai_addr, res->ai_addrlen, q->ans.recs[i_rec],
                            DNS_MAX_ANS_RR_LEN, NULL, 0, NI_NUMERICHOST);
          if (ret)
          {
            PUTS_OSYS(LOG_ERR, " Failed to translate address to name!");
            continue;
          }

          PUTS_OSYS(LOG_DEBUG, " recs[%d]: [%s]", i_rec, q->ans.recs[i_rec]);
          PUTS_OSYS(LOG_DEBUG, " ai_canonname: [%s]", res->ai_canonname);
          i_rec++;
        }

        q->ans.n_rec = i_rec;
      }
    }
  }

  ret = add_src_dest_to_whitelist(src_addr, qs, n_qs);
  if (ret)
  {
    goto EXIT;
  }

  ret = RET_OK;

  EXIT:

  if (res0 != NULL)
  {
    freeaddrinfo(res0);
  }

  return(ret);
}

