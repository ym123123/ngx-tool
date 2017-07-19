/*
 * ngx_redis.c
 *
 *  Created on: 2017年7月19日
 *      Author: ym
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <hiredis/hiredis.h>

#include "ngx_redis.h"

static ngx_core_module_t ngx_core_redis_module =
{
		ngx_string("redis"),
		NULL,
		NULL
};

ngx_module_t ngx_redis_module =
{
		NGX_MODULE_V1,
		&ngx_core_redis_module,
		NULL,
		NGX_CORE_MODULE,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NGX_MODULE_V1_PADDING
};

static int intlen(int i) {
    int len = 0;
    if (i < 0) {
        len++;
        i = -i;
    }
    do {
        len++;
        i /= 10;
    } while(i);
    return len;
}

static size_t bulklen(size_t len) {
    return 1+intlen(len)+2+len+2;
}

static ngx_buf_t *ngx_redis_command_argv(ngx_pool_t *pool, int argc, const char **argv, const size_t *argvlen) {
    size_t len;
    int totlen, j;
    ngx_buf_t *buf;

    /* Calculate number of bytes needed for the command */
    totlen = 1+intlen(argc)+2;
    for (j = 0; j < argc; j++) {
        len = argvlen ? argvlen[j] : strlen(argv[j]);
        totlen += bulklen(len);
    }

    buf = ngx_create_temp_buf(pool, totlen);
    if (buf == NULL)
        return NULL;

    buf->last = ngx_sprintf(buf->last, "*%d\r\n", argc);

    for (j = 0; j < argc; j++) {
        len = argvlen ? argvlen[j] : strlen(argv[j]);
        buf->last = ngx_sprintf(buf->last,"$%zu\r\n",len);
        ngx_memcpy(buf->last, argv[j], len);
        *buf->last++ = '\r';
        *buf->last++ = '\n';
    }

    return buf;
}

/*
 * pool 内存池
 * cmd 命令
 * return 需要发送的数据
 */
ngx_buf_t *ngx_redis_command(ngx_pool_t *pool, ngx_array_t *cmd)
{
	const char *argv[128];
	size_t sizes[128];
	ngx_uint_t i;
	ngx_str_t *values;

	if (cmd->nelts > 128)
	{
		return NULL;
	}

	values = cmd->elts;
	for (i = 0; i < cmd->nelts; i++)
	{
		argv[i] = (const char *)values[i].data;
		sizes[i] = values[i].len;
	}

	return ngx_redis_command_argv(pool, i, argv, sizes);
}

redisReader *ngx_redis_create_reader()
{
	return redisReaderCreate();
}

void ngx_redis_destroy_reader(redisReader *reader)
{
	if (reader != NULL)
		redisReaderFree(reader);
}

ngx_int_t ngx_redis_parse_data(redisReader *reader, ngx_buf_t *buf, ngx_redis_reply_t **reply)
{
	if (redisReaderFeed(reader, (const char *)buf->pos, buf->last - buf->pos) == REDIS_ERR)
	{
		return NGX_ERROR;
	}

	buf->last = buf->pos;

	if (redisReaderGetReply(reader, (void **)reply) == REDIS_ERR)
	{
		return NGX_ERROR;
	}

	if (*reply == NULL)
	{
		return NGX_AGAIN;
	}

	return NGX_OK;
}
