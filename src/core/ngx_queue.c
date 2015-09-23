
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * find the middle queue element if the queue has odd number of elements
 * or the first element of the queue's second part otherwise
 */

ngx_queue_t *
ngx_queue_middle(ngx_queue_t *queue)
{
    ngx_queue_t  *middle, *next;

	//获取到头
    middle = ngx_queue_head(queue);

	//如果存在一个元素那就是middle 如果不存在 那就是NULL
    if (middle == ngx_queue_last(queue)) {
        return middle;
    }

	//获取到头
    next = ngx_queue_head(queue);

	//next 每次循环走两步 当 next走到头 middle正好走到中间
    for ( ;; ) {
		//获取到下一个节点
        middle = ngx_queue_next(middle);

		//获取到下一个节点
        next = ngx_queue_next(next);

		//如果next是最后一个 
        if (next == ngx_queue_last(queue)) {
            return middle;
        }

		//走两回
        next = ngx_queue_next(next);

        if (next == ngx_queue_last(queue)) {
            return middle;
        }
    }
}


/* the stable insertion sort */

void
ngx_queue_sort(ngx_queue_t *queue,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *))
{
    ngx_queue_t  *q, *prev, *next;

	//获取首个元素
    q = ngx_queue_head(queue);

	//空链表
    if (q == ngx_queue_last(queue)) {
        return;
    }

	//排序
    for (q = ngx_queue_next(q); q != ngx_queue_sentinel(queue); q = next) {

		//获取前一个
        prev = ngx_queue_prev(q);
		//获取后一个
        next = ngx_queue_next(q);

		//删除Q 
        ngx_queue_remove(q);

		//和前别元素进行比较
        do {
            if (cmp(prev, q) <= 0) {
                break;
            }

            prev = ngx_queue_prev(prev);

        } while (prev != ngx_queue_sentinel(queue));

		//将Q插入到比他小的元素前边队列中
        ngx_queue_insert_after(prev, q);
    }
}
