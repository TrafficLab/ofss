/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

/*
 * Helper structure and macros for the utlist library.
 */

#ifndef LIST_H
#define LIST_H 1

struct list_node {
    struct list_node *next;
    struct list_node *prev;
};


#define DL_PREPEND_ELEM(head, el, add)                                                         \
do {                                                                                           \
 (add)->next = (el);                                                                           \
 (add)->prev = (el)->prev;                                                                     \
 (el)->prev = (add);                                                                           \
 if ((head) == (el)) {                                                                         \
  (head) = (add);                                                                              \
 } else {                                                                                      \
  (add)->prev->next = (add);                                                                   \
 }                                                                                             \
} while (0)                                                                                    \


#define DL_REPLACE_ELEM(head, el, add)                                                         \
do {                                                                                           \
 if ((head) == (el)) {                                                                         \
  (head) = (add);                                                                              \
  (add)->next = (el)->next;                                                                    \
  if ((el)->next == NULL) {                                                                    \
   (add)->prev = (add);                                                                        \
  } else {                                                                                     \
   (add)->prev = (el)->prev;                                                                   \
   (add)->next->prev = (add);                                                                  \
  }                                                                                            \
 } else {                                                                                      \
  (add)->next = (el)->next;                                                                    \
  (add)->prev = (el)->prev;                                                                    \
  (add)->prev->next = (add);                                                                   \
  if ((el)->next == NULL) {                                                                    \
   (head)->prev = (add);                                                                       \
  } else {                                                                                     \
   (add)->next->prev = (add);                                                                  \
  }                                                                                            \
 }                                                                                             \
} while (0)



#endif /* LIST_H */
