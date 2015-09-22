
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;//操作函数的指针
    void                 *data;/*内存本身*/
    ngx_pool_cleanup_t   *next;/*下一个节点*/
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next;/*下一个节点*/
    void                 *alloc;/*内存本身*/
};


typedef struct {
    u_char               *last;/*当前数据长度*/
    u_char               *end;/*分配的内存最大长度*/
    ngx_pool_t           *next;/*下一个ngx_pool_s节点*/
    ngx_uint_t            failed;/*?????*/
} ngx_pool_data_t;


struct ngx_pool_s {
    ngx_pool_data_t       d; /*内存池数据*/
    size_t                max;/*当前内存池剩余的空间*/
    ngx_pool_t           *current;/*ngx_pool_s节点本身*/
    ngx_chain_t          *chain;/*?????*/
    ngx_pool_large_t     *large;/*大块内存*/
    ngx_pool_cleanup_t   *cleanup;//自定义的内存 以及内存释放
    ngx_log_t            *log;/*记录日志的信息*/
};


typedef struct {
    ngx_fd_t              fd;/*封装的文件句柄*/
    u_char               *name;/*文件名????*/
    ngx_log_t            *log;/*日志信息*/
} ngx_pool_cleanup_file_t;


void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
