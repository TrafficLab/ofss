/* Copyright (c) 2011-2012, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * The contents of this file are subject to the license defined in
 * file 'doc/LICENSE', which is part of this source code package.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef OFL_UTILS_H
#define OFL_UTILS_H 1


#include <netinet/in.h>


/* Given an array of pointers _elem_, and the number of elements in the array
   _elem_num_, this function frees each element, as well as the array
   itself. */
#define OFL_UTILS_FREE_ARR(ELEMS, ELEM_NUM)     \
{                                               \
     size_t _iter;                              \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {   \
         free(ELEMS[_iter]);                    \
     }                                          \
     free(ELEMS);                               \
}

 /* Given an array of pointers _elem_, and the number of elements in the array
    _elem_num_, this function frees each element using the provided _free_fun_
    function, and frees the array itself as well. */
#define OFL_UTILS_FREE_ARR_FUN(ELEMS, ELEM_NUM, FREE_FUN) \
{                                               \
     size_t _iter;                              \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {   \
         FREE_FUN(ELEMS[_iter]);                \
     }                                          \
     free(ELEMS);                               \
}

#define OFL_UTILS_FREE_ARR_FUN2(ELEMS, ELEM_NUM, FREE_FUN, ARG2) \
{                                                \
     size_t _iter;                               \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {    \
         FREE_FUN(ELEMS[_iter], ARG2);           \
     }                                           \
     free(ELEMS);                                \
}

#define OFL_UTILS_FREE_ARR_FUN3(ELEMS, ELEM_NUM, FREE_FUN, ARG2, ARG3) \
{                                                \
     size_t _iter;                               \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {    \
         FREE_FUN(ELEMS[_iter], ARG2, ARG3);     \
     }                                           \
     free(ELEMS);                                \
}



/* Given an array of pointers _elem_, and the number of elements in the array
   _elem_num_, this function sums the result of calling the provided _len_fun_
   function for each element. */
#define OFL_UTILS_SUM_ARR_FUN(RESULT, ELEMS, ELEM_NUM, LEN_FUN) \
{                                                \
     size_t _iter, _ret;                         \
                                                 \
     _ret = 0;                                   \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {    \
         _ret += LEN_FUN(ELEMS[_iter]);          \
     }                                           \
                                                 \
     RESULT = _ret;                              \
}


#define OFL_UTILS_SUM_ARR_FUN2(RESULT, ELEMS, ELEM_NUM, LEN_FUN, ARG2) \
{                                                    \
     size_t _iter, _ret;                             \
                                                     \
     _ret = 0;                                       \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {        \
         _ret += LEN_FUN(ELEMS[_iter], ARG2);        \
     }                                               \
                                                     \
     RESULT = _ret;                                  \
}


#define OFL_UTILS_SUM_ARR_FUN3(RESULT, ELEMS, ELEM_NUM, LEN_FUN, ARG2, ARG3) \
{                                                    \
     size_t _iter, _ret;                             \
                                                     \
     _ret = 0;                                       \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {        \
         _ret += LEN_FUN(ELEMS[_iter], ARG2, ARG3);  \
     }                                               \
                                                     \
     RESULT = _ret;                                  \
}


static inline uint64_t
hton64(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)htonl(n)) << 32) + htonl(n >> 32);
#endif
}

static inline uint64_t
ntoh64(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)ntohl(n)) << 32) + ntohl(n >> 32);
#endif
}


#endif /* OFL_UTILS_H */
