/*INC+*************************************************************************/
/* Filename    : llist.h                                                      */
/*                                                                            */
/* Description : Linked-list header file.                                     */
/*                                                                            */
/* Revisions   : 05/12/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _LLIST_H
#define _LLIST_H

/******************************************************************************/
/* List.                                                                      */
/******************************************************************************/
typedef struct _llist
{
  void *head;
  void *tail;
} llist;


typedef struct _llitem
{
  void *next;
} llitem;


/******************************************************************************/
/* Forwards decls.                                                            */
/******************************************************************************/
extern void llist_add(llist *ll, llitem *item);
extern void llist_clean(llist *ll);

#endif
