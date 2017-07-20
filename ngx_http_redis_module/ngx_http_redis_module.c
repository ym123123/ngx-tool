/*
 * ngx_http_redis_module.c
 *
 *  Created on: 2017年7月19日
 *      Author: ym
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../redis/ngx_redis.h"

typedef struct
{
	ngx_http_upstream_conf_t upstream;
} ngx_http_redis_loc_t;

static void *ngx_http_redis_loc_create(ngx_conf_t *cf);
static char *ngx_http_redis_loc_merge(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_redis_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_redis_parse(ngx_http_request_t *r);

static ngx_int_t ngx_http_redis_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_process_header(ngx_http_request_t *r);
static void ngx_http_redis_abort_request(ngx_http_request_t *r);
static void ngx_http_redis_finalize_request(ngx_http_request_t *r, ngx_int_t rc);


static ngx_int_t ngx_http_redis_input_filter_init(void *data);
static ngx_int_t ngx_http_redis_input_filter(void *data, ssize_t bytes);

static ngx_command_t ngx_http_redis_commands[] =
{
		{
				ngx_string("redis_pass"),
				NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
				ngx_http_redis_block,
				NGX_HTTP_LOC_CONF_OFFSET,
				0,
				NULL
		},
		ngx_null_command
};

static ngx_http_module_t ngx_http_redis_ctx =
{
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		ngx_http_redis_loc_create,
		ngx_http_redis_loc_merge
};

ngx_module_t ngx_http_redis_module =
{
		NGX_MODULE_V1,
		&ngx_http_redis_ctx,
		ngx_http_redis_commands,
		NGX_HTTP_MODULE,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_redis_create_request(ngx_http_request_t *r)
{
	ngx_http_upstream_t *u = r->upstream;
	ngx_array_t *cmd = (ngx_array_t *)r->args.data;
	ngx_chain_t *out;
	ngx_buf_t *buf = ngx_redis_command(r->pool, cmd);
	out = ngx_alloc_chain_link(r->pool);

	if (buf == NULL || out == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, "parse request error.");
		return NGX_ERROR;
	}

	out->buf = buf;
	out->next = NULL;

	u->request_bufs = out;
	return NGX_OK;
}


static ngx_int_t ngx_http_redis_reinit_request(ngx_http_request_t *r)
{
	return NGX_OK;
}

void test_redis_print(ngx_redis_reply_t *reply)
{
	size_t i;

	switch(reply->type)
	{
	case REDIS_REPLY_INTEGER:
		printf("%d\n", (int)reply->integer);
		break;
	case REDIS_REPLY_ARRAY:

		for (i = 0; i < reply->elements; i++)
		{
			test_redis_print(reply->element[i]);
		}

		break;
	default:
		printf("%s\n", reply->str);
		break;
	}
}

static ngx_int_t ngx_http_redis_process_header(ngx_http_request_t *r)
{
	ngx_pool_cleanup_t *cln;
	ngx_int_t rc;
	ngx_http_upstream_t *u;
	ngx_redis_reply_t *reply;
	ngx_redis_ctx_t *reader = ngx_http_get_module_ctx(r, ngx_http_redis_module);

	if (reader == NULL)
	{
		reader = ngx_redis_create_reader();
		cln = ngx_pool_cleanup_add(r->pool, 0);

		if (reader == NULL || cln == NULL)
		{
			ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, "create reader error.");
			return NGX_ERROR;
		}

		ngx_http_set_ctx(r, reader, ngx_http_redis_module);
		cln->handler = (ngx_http_cleanup_pt)ngx_redis_destroy_reader;
		cln->data = reader;
	}

	rc = ngx_redis_parse_data(reader, &r->upstream->buffer, &reply);

	if (rc != NGX_OK)
		return rc;
	//parse reply....
	test_redis_print(reply);

	u = r->upstream;

	u->headers_in.content_length_n = 0;
	u->headers_in.status_n = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "text/plain");

	return rc;
}

static void ngx_http_redis_abort_request(ngx_http_request_t *r)
{

}

static void ngx_http_redis_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
	ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, "ok");
}

static ngx_int_t ngx_http_redis_input_filter_init(void *data)
{
    ngx_http_request_t *r = data;

    ngx_http_upstream_t *u;

    u = r->upstream;

    if (u->headers_in.status_n != NGX_HTTP_NOT_FOUND)
    {
        u->length = u->headers_in.content_length_n;
    }
    else
    {
        u->length = 0;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_redis_input_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t  *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return NGX_OK;
    }

    u->length -= bytes;

    return NGX_OK;
}

static ngx_int_t ngx_http_redis_parse(ngx_http_request_t *r)
{
	ngx_http_upstream_t *u;
	ngx_http_redis_loc_t *conf;
	ngx_int_t rc;

	{//test
		ngx_str_t *str;
		ngx_array_t *cmd = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));

		if (cmd == NULL)
		{
			ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, "no memory.");
			return NGX_ERROR;
		}

		str = ngx_array_push(cmd);
		ngx_str_set(str, "lrange");
		str = ngx_array_push(cmd);
		ngx_str_set(str, "aaa");
		str = ngx_array_push(cmd);
		ngx_str_set(str, "0");

		str = ngx_array_push(cmd);
		ngx_str_set(str, "-1");
		r->args.data = (void *)cmd;
		r->args.len = sizeof(ngx_array_t);
	}

	if (r->args.data == NULL || r->args.len != sizeof(ngx_array_t))
	{
		ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, "inval url args");
		return NGX_ERROR;
	}

	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK)
		return rc;

	if (ngx_http_set_content_type(r) != NGX_OK)
	{
		ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, "set content type error.");
		return NGX_ERROR;
	}

	if (ngx_http_upstream_create(r) != NGX_OK)
	{
		ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, "create upstream error.");
		return NGX_ERROR;
	}

	conf = ngx_http_get_module_loc_conf(r, ngx_http_redis_module);
	u = r->upstream;

	ngx_str_set(&u->schema, "redis://");
	u->output.tag = (ngx_buf_tag_t)&ngx_http_redis_module;
	u->buffering = 0;
	u->conf = &conf->upstream;

	u->create_request = ngx_http_redis_create_request;
	u->reinit_request = ngx_http_redis_reinit_request;
	u->process_header = ngx_http_redis_process_header;
	u->abort_request = ngx_http_redis_abort_request;
	u->finalize_request = ngx_http_redis_finalize_request;

	u->input_filter_ctx = r;
	u->input_filter_init = ngx_http_redis_input_filter_init;
	u->input_filter = ngx_http_redis_input_filter;

	r->main->count++;
	ngx_http_upstream_init(r);
	return NGX_DONE;
}

static char *ngx_http_redis_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_redis_loc_t *redis = conf;
	ngx_url_t u;
	ngx_str_t *value = cf->args->elts;
	ngx_http_core_loc_conf_t *clcf;

	ngx_memzero(&u, sizeof(u));
	u.url = value[1];
	u.no_resolve = 1;

	if ((redis->upstream.upstream = ngx_http_upstream_add(cf, &u, 0)) == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG, cf->log, 0, "no memory.");
		return NGX_CONF_ERROR;
	}

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	if (clcf->name.data[clcf->name.len - 1] == '/')
		clcf->auto_redirect = 1;

	clcf->handler = ngx_http_redis_parse;
	return NGX_CONF_OK;
}

static void *ngx_http_redis_loc_create(ngx_conf_t *cf)
{
	ngx_http_redis_loc_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));

	if (conf == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG, cf->log, 0, "no memory.");
		return NULL;
	}

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;
    conf->upstream.force_ranges = 1;

	return conf;
}
static char *ngx_http_redis_loc_merge(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_redis_loc_t *prev = parent;
    ngx_http_redis_loc_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    return NGX_CONF_OK;
}
