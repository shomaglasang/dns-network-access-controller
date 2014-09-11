/*FILE+************************************************************************/
/* Filename    : response.c                                                   */
/*                                                                            */
/* Description : Routines to process DNS response.                            */
/*                                                                            */
/* Revisions   : 05/29/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <common.h>
#include <dnswldcb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


/*FUNC+************************************************************************/
/* Function    : process_response                                             */
/*                                                                            */
/* Description : Process DNS response.                                        */
/*                                                                            */
/* Params      : listener (IN)            - Listener CB.                      */
/*               d_addr (IN)              - Destination address.              */
/*               last (IN)                - Pointer to last part of request.  */
/*               dns_hdr (IN)             - DNS header.                       */
/*               q (IN)                   - Questions with answers.           */
/*                                                                            */
/* Returns     : RET_OK                   - Success otherwise error.          */
/*                                                                            */
/*FUNC-************************************************************************/
int process_response(listeners_cb *listener, struct sockaddr_in *d_addr,
                     char *last, dns_header *dns_hdr, dns_question *q)
{
  unsigned short fc = 0;
  int pkt_len;
  int label_len;
  int i;
  int ii;
  int ret;

  PUTS_OSYS(LOG_DEBUG, "Processing response ...");

  /****************************************************************************/
  /* Update DNS header.                                                       */
  /****************************************************************************/
  dns_hdr->id = ntohs(dns_hdr->id);
  fc |= DNS_HDR_QR_RESP;
  dns_hdr->q_count = htons(dns_hdr->q_count);

  pkt_len = last - dnswld.proc.pkt_buf;

  if (q->ans.n_rec > 0)
  {
    fc |= DNS_HDR_RCODE_NO_ERR;
    dns_hdr->ans_count = htons(q->ans.n_rec);

    /**************************************************************************/
    /* Encode answers.                                                        */
    /**************************************************************************/
    for (i = 0; i < q->ans.n_rec; i++)
    {
      for (ii = 0; ii < q->n_label; ii++)
      {
        label_len = strlen(q->labels[ii]);
        *last = label_len;
        last++;
        memcpy(last, q->labels[ii], label_len);
        last += label_len;
      }

      *last = 0;
      last++;

      pkt_len = last - dnswld.proc.pkt_buf;

      *((unsigned short *)last) = htons(DNS_RR_TYPE_A);
      last += sizeof(unsigned short);

      *((unsigned short *)last) = htons(DNS_RR_CLASS_IN);
      last += sizeof(unsigned short);

      *((unsigned int *)last) = 0;
      last += sizeof(unsigned int);

      *((unsigned short *)last) = htons(DNS_RR_TYPE_A_LEN);
      last += sizeof(unsigned short);

      /************************************************************************/
      /* Encode resource data.                                                */
      /************************************************************************/
      PUTS_OSYS(LOG_DEBUG, " rec[%d]: [%s]", i, q->ans.recs[i]);
      inet_aton(q->ans.recs[i], (struct in_addr *)last);
      last += DNS_RR_TYPE_A_LEN;
    }
  }
  else
  {
    fc |= DNS_HDR_RCODE_NAME_ERR;
  }

  dns_hdr->fc = fc;
  pkt_len = last - dnswld.proc.pkt_buf;
  PUTS_OSYS(LOG_DEBUG, "pkt_len: [%d]", pkt_len);

  /****************************************************************************/
  /* Send reply.                                                              */
  /****************************************************************************/
  ret = sendto(listener->sock, dnswld.proc.pkt_buf, pkt_len, 0,
               (struct sockaddr *)d_addr, sizeof(struct sockaddr));
  if (ret != pkt_len)
  {
    PUTS_OSYS(LOG_ERR, "Error in sending response. ret: [%d]", ret);
    ret = RET_SOCK_WRITE_ERROR;
    goto EXIT;
  }

  ret = RET_OK;

  EXIT:

  return(ret);
}

