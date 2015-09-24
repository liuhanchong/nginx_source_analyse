
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) Ruslan Ermilov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_thread_pool.h>


typedef struct {
    ngx_array_t               pools;
} ngx_thread_pool_conf_t;


typedef struct {
    ngx_thread_task_t        *first;
    ngx_thread_task_t       **last;
} ngx_thread_pool_queue_t;

//将第一个元素的地址传递给last作为下一个元素起始点
#define ngx_thread_pool_queue_init(q)                                         \
    (q)->first = NULL;                                                        \
    (q)->last = &(q)->first 


struct ngx_thread_pool_s {
    ngx_thread_mutex_t        mtx;//线程池互斥信号
    ngx_thread_pool_queue_t   queue;/*池队列*/
    ngx_int_t                 waiting;/*等待任务队列*/
    ngx_thread_cond_t         cond;/*条件变量*/

    ngx_log_t                *log;/*日志信息*/

    ngx_str_t                 name;
    ngx_uint_t                threads;/*线程个数*/
    ngx_int_t                 max_queue;/*队列最大长度*/

    u_char                   *file;
    ngx_uint_t                line;
};


static ngx_int_t ngx_thread_pool_init(ngx_thread_pool_t *tp, ngx_log_t *log,
    ngx_pool_t *pool);
static void ngx_thread_pool_destroy(ngx_thread_pool_t *tp);
static void ngx_thread_pool_exit_handler(void *data, ngx_log_t *log);

static void *ngx_thread_pool_cycle(void *data);
static void ngx_thread_pool_handler(ngx_event_t *ev);

static char *ngx_thread_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_thread_pool_create_conf(ngx_cycle_t *cycle);
static char *ngx_thread_pool_init_conf(ngx_cycle_t *cycle, void *conf);

static ngx_int_t ngx_thread_pool_init_worker(ngx_cycle_t *cycle);
static void ngx_thread_pool_exit_worker(ngx_cycle_t *cycle);


static ngx_command_t  ngx_thread_pool_commands[] = {

    { ngx_string("thread_pool"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE23,
      ngx_thread_pool,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_thread_pool_module_ctx = {
    ngx_string("thread_pool"),
    ngx_thread_pool_create_conf,
    ngx_thread_pool_init_conf
};


ngx_module_t  ngx_thread_pool_module = {
    NGX_MODULE_V1,
    &ngx_thread_pool_module_ctx,           /* module context */
    ngx_thread_pool_commands,              /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_thread_pool_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_thread_pool_exit_worker,           /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_thread_pool_default = ngx_string("default");

static ngx_uint_t               ngx_thread_pool_task_id;
static ngx_atomic_t             ngx_thread_pool_done_lock;
static ngx_thread_pool_queue_t  ngx_thread_pool_done;


static ngx_int_t
ngx_thread_pool_init(ngx_thread_pool_t *tp, ngx_log_t *log, ngx_pool_t *pool/*pool此处并未用到*/)
{
	//tp 在传递进来之前已经进行了部分数据的初始化
	/*threads 线程个数
	 *waiting 初始化为多少
	 */
	
    int             err;
    pthread_t       tid;
    ngx_uint_t      n;
    pthread_attr_t  attr;

	//这是什么 在ngx_event 中定义的宏变量
    if (ngx_notify == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
               "the configured event method cannot be used with thread pools");
        return NGX_ERROR;
    }

	//初始化队列
    ngx_thread_pool_queue_init(&tp->queue);

	//创建信号 这地方的使用的是unix/linux类似的系统调用
    if (ngx_thread_mutex_create(&tp->mtx, log) != NGX_OK) {
        return NGX_ERROR;
    }

	//初始化条件变量
    if (ngx_thread_cond_create(&tp->cond, log) != NGX_OK) {
        (void) ngx_thread_mutex_destroy(&tp->mtx, log);
        return NGX_ERROR;
    }

	//保存日志
    tp->log = log;

	//初始化线程属性
    err = pthread_attr_init(&attr);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
                      "pthread_attr_init() failed");
        return NGX_ERROR;
    }

	//目前这部分不执行
#if 0
	//设置线程栈的大小
    err = pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
                      "pthread_attr_setstacksize() failed");
        return NGX_ERROR;
    }
#endif

	//创建threads个线程
    for (n = 0; n < tp->threads; n++) {
		//设置线程的执行函数ngx_thread_pool_cycle以及传递数据tp
        err = pthread_create(&tid, &attr, ngx_thread_pool_cycle, tp);
        if (err) {
            ngx_log_error(NGX_LOG_ALERT, log, err,
                          "pthread_create() failed");
            return NGX_ERROR;
        }
    }

	//销毁线程属性
    (void) pthread_attr_destroy(&attr);

    return NGX_OK;
}


static void
ngx_thread_pool_destroy(ngx_thread_pool_t *tp)
{
    ngx_uint_t           n;
    ngx_thread_task_t    task;
    volatile ngx_uint_t  lock;//多线程

    ngx_memzero(&task, sizeof(ngx_thread_task_t));

	//退出任务操作
    task.handler = ngx_thread_pool_exit_handler;
    task.ctx = (void *) &lock;//标志

	//遍历多个线程
    for (n = 0; n < tp->threads; n++) {
        lock = 1;

		//将任务加入到队列
        if (ngx_thread_task_post(tp, &task) != NGX_OK) {
            return;
        }

        while (lock) {
			/*优先执行其他线程*/
            ngx_sched_yield();
        }

		//释放了一个线程
        task.event.active = 0;
    }

	//销毁条件变量
    (void) ngx_thread_cond_destroy(&tp->cond, tp->log);

	//销毁互斥量
    (void) ngx_thread_mutex_destroy(&tp->mtx, tp->log);
}


static void
ngx_thread_pool_exit_handler(void *data, ngx_log_t *log)
{
    ngx_uint_t *lock = data;

	//解锁 准备释放下一个
    *lock = 0;

    pthread_exit(0);
}

/*分配任务节点 以及 数据大小*/
ngx_thread_task_t *
ngx_thread_task_alloc(ngx_pool_t *pool, size_t size)
{
    ngx_thread_task_t  *task;

	//分配任务节点 并分配保存数据的内存
    task = ngx_pcalloc(pool, sizeof(ngx_thread_task_t) + size);
    if (task == NULL) {
        return NULL;
    }

    task->ctx = task + 1;

    return task;
}


/*加入任务队列*/
ngx_int_t
ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task)
{
	//是否事件已经触发
    if (task->event.active) {
        ngx_log_error(NGX_LOG_ALERT, tp->log, 0,
                      "task #%ui already active", task->id);
        return NGX_ERROR;
    }

	//锁住互斥锁
    if (ngx_thread_mutex_lock(&tp->mtx, tp->log) != NGX_OK) {
        return NGX_ERROR;
    }

	//如果等待的个数大于队列最大数量
    if (tp->waiting >= tp->max_queue) {
        (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);

        ngx_log_error(NGX_LOG_ERR, tp->log, 0,
                      "thread pool \"%V\" queue overflow: %i tasks waiting",
                      &tp->name, tp->waiting);
        return NGX_ERROR;
    }

	//激活事件
    task->event.active = 1;

	//新的任务ID
    task->id = ngx_thread_pool_task_id++;
    task->next = NULL;

	//发送信号 如果队列为空 还是不能保证激活线程
    if (ngx_thread_cond_signal(&tp->cond, tp->log) != NGX_OK) {
        (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
        return NGX_ERROR;
    }

    *tp->queue.last = task;/*将当前任务加入到队列最后*/
    tp->queue.last = &task->next;//保存下一个地址的地址，将之后的任务保存在这地方

    tp->waiting++;/*增加等待的个数*/

	/*解锁互斥锁*/
    (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
                   "task #%ui added to thread pool \"%V\"",
                   task->id, &tp->name);

    return NGX_OK;
}

/*每个线程 循环处理获取到的任务 
  其将任务队列和线程池绑定*/
static void *
ngx_thread_pool_cycle(void *data)
{
	/*获取传递的数据*/
    ngx_thread_pool_t *tp = data;

    int                 err;
    sigset_t            set;/*信号集*/
    ngx_thread_task_t  *task;/*任务*/

	//暂时不使用
#if 0
    ngx_time_update();
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, tp->log, 0,
                   "thread in pool \"%V\" started", &tp->name);

	//将所有的信号集加入到集合
    sigfillset(&set);

	//将下面的信号移除
    sigdelset(&set, SIGILL);
    sigdelset(&set, SIGFPE);
    sigdelset(&set, SIGSEGV);
    sigdelset(&set, SIGBUS);

	//在主线程中处理信号 此线程不处理这些信号
    err = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, tp->log, err, "pthread_sigmask() failed");
        return NULL;
    }

	//循环处理任务
    for ( ;; ) {
		//获取线程池锁
        if (ngx_thread_mutex_lock(&tp->mtx, tp->log) != NGX_OK) {
            return NULL;
        }

        /* the number may become negative */
		/*减少等待的队列*/
        tp->waiting--;

        while (tp->queue.first == NULL) {
			/*等待任务队列触发*/
            if (ngx_thread_cond_wait(&tp->cond, &tp->mtx, tp->log)
                != NGX_OK)
            {
                (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
                return NULL;
            }
        }

		//获取一个任务先进先出
        task = tp->queue.first;
        tp->queue.first = task->next;

		//队列为空 将最后一个指向第一个
        if (tp->queue.first == NULL) {
            tp->queue.last = &tp->queue.first;
        }

		//解锁
        if (ngx_thread_mutex_unlock(&tp->mtx, tp->log) != NGX_OK) {
            return NULL;
        }

		//暂时不使用
#if 0
        ngx_time_update();
#endif

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
                       "run task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

		//处理任务
        task->handler(task->ctx, tp->log);

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
                       "complete task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

		/*将下一个任务指向空*/
        task->next = NULL;

		/*这一部分是对ngx_thread_pool_done变量进行赋值*/
        ngx_spinlock(&ngx_thread_pool_done_lock, 1, 2048);

        *ngx_thread_pool_done.last = task;
        ngx_thread_pool_done.last = &task->next;

        ngx_unlock(&ngx_thread_pool_done_lock);

		/*???????????????*/
        (void) ngx_notify(ngx_thread_pool_handler);
    }
}

/*暂时不明白这个函数的用意*/
static void
ngx_thread_pool_handler(ngx_event_t *ev)
{
    ngx_event_t        *event;
    ngx_thread_task_t  *task;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "thread pool handler");

	//获取到任务
    ngx_spinlock(&ngx_thread_pool_done_lock, 1, 2048);

    task = ngx_thread_pool_done.first;
    ngx_thread_pool_done.first = NULL;
    ngx_thread_pool_done.last = &ngx_thread_pool_done.first;

    ngx_unlock(&ngx_thread_pool_done_lock);

    while (task) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "run completion handler for task #%ui", task->id);

        event = &task->event;
        task = task->next;

        event->complete = 1;
        event->active = 0;

        event->handler(event);
    }
}

/*初始化线程池数组*/
static void *
ngx_thread_pool_create_conf(ngx_cycle_t *cycle)
{
    ngx_thread_pool_conf_t  *tcf;

	//从线程池中分配ngx_thread_pool_conf_t
    tcf = ngx_pcalloc(cycle->pool, sizeof(ngx_thread_pool_conf_t));
    if (tcf == NULL) {
        return NULL;
    }

	//分配线程池指针数组大小为4
    if (ngx_array_init(&tcf->pools, cycle->pool, 4,
                       sizeof(ngx_thread_pool_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return tcf;
}

/*初始化配置*/
static char *
ngx_thread_pool_init_conf(ngx_cycle_t *cycle, void *conf)
{
	/*获取到配置*/
    ngx_thread_pool_conf_t *tcf = conf;

    ngx_uint_t           i;
    ngx_thread_pool_t  **tpp;

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {

		//如果存在线程
        if (tpp[i]->threads) {
            continue;
        }

        if (tpp[i]->name.len == ngx_thread_pool_default.len
            && ngx_strncmp(tpp[i]->name.data, ngx_thread_pool_default.data,
                           ngx_thread_pool_default.len)
               == 0)
        {
			//最大线程数 32 队列最大 65536
            tpp[i]->threads = 32;
            tpp[i]->max_queue = 65536;
            continue;
        }

        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "unknown thread pool \"%V\" in %s:%ui",
                      &tpp[i]->name, tpp[i]->file, tpp[i]->line);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

//初始化线程信息
static char *
ngx_thread_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t          *value;
    ngx_uint_t          i;
    ngx_thread_pool_t  *tp;

    value = cf->args->elts;

	//增加一个线程池
    tp = ngx_thread_pool_add(cf, &value[1]);

    if (tp == NULL) {
        return NGX_CONF_ERROR;
    }

	//线程池已存在
    if (tp->threads) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate thread pool \"%V\"", &tp->name);
        return NGX_CONF_ERROR;
    }

	//最大队列
    tp->max_queue = 65536;

	//
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "threads=", 8) == 0) {

			//解析线程数
            tp->threads = ngx_atoi(value[i].data + 8, value[i].len - 8);

			//判断线程数是否无效
            if (tp->threads == (ngx_uint_t) NGX_ERROR || tp->threads == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid threads value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

		/*获取最大队列数*/
        if (ngx_strncmp(value[i].data, "max_queue=", 10) == 0) {

			//解析最大队列数
            tp->max_queue = ngx_atoi(value[i].data + 10, value[i].len - 10);

			//判断队列数是否无效
            if (tp->max_queue == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max_queue value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }
    }

	//线程数为0
    if (tp->threads == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"threads\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*加入一个线程池*/
ngx_thread_pool_t *
ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_thread_pool_t       *tp, **tpp;
    ngx_thread_pool_conf_t  *tcf;

	//当名字为空 设置默认值
    if (name == NULL) {
        name = &ngx_thread_pool_default;
    }

	//获取一个线程池指针
    tp = ngx_thread_pool_get(cf->cycle, name);

	//如果存在 那么返回获取到的线程池
    if (tp) {
        return tp;
    }

	//分配一个ngx_thread_pool_t
    tp = ngx_pcalloc(cf->pool, sizeof(ngx_thread_pool_t));
    if (tp == NULL) {
        return NULL;
    }

	//保存基本信息
    tp->name = *name;
    tp->file = cf->conf_file->file.name.data;
    tp->line = cf->conf_file->line;

	//获取线程池配置
    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                  ngx_thread_pool_module);

	//将新的线程池加入
    tpp = ngx_array_push(&tcf->pools);
    if (tpp == NULL) {
        return NULL;
    }

	//保存线程池
    *tpp = tp;

    return tp;
}


ngx_thread_pool_t *
ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_uint_t                i;
    ngx_thread_pool_t       **tpp;
    ngx_thread_pool_conf_t   *tcf;

	//获取配置信息
    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_thread_pool_module);

	//获取到线程池指针数组
    tpp = tcf->pools.elts;

	//获取一个名字相同的线程池指针
    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->name.len == name->len
            && ngx_strncmp(tpp[i]->name.data, name->data, name->len) == 0)
        {
            return tpp[i];
        }
    }

    return NULL;
}

/**/
static ngx_int_t
ngx_thread_pool_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                i;
    ngx_thread_pool_t       **tpp;
    ngx_thread_pool_conf_t   *tcf;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

	//获取线程池配置
    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    if (tcf == NULL) {
        return NGX_OK;
    }

	//初始化队列
    ngx_thread_pool_queue_init(&ngx_thread_pool_done);

	//获取线程池数组
    tpp = tcf->pools.elts;

	//初始化线程池数组
    for (i = 0; i < tcf->pools.nelts; i++) {
        if (ngx_thread_pool_init(tpp[i], cycle->log, cycle->pool) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_thread_pool_exit_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                i;
    ngx_thread_pool_t       **tpp;
    ngx_thread_pool_conf_t   *tcf;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return;
    }

	//获取线程池配置
    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    if (tcf == NULL) {
        return;
    }

	//获取线程池数组
    tpp = tcf->pools.elts;

	//销毁线程池
    for (i = 0; i < tcf->pools.nelts; i++) {
        ngx_thread_pool_destroy(tpp[i]);
    }
}
