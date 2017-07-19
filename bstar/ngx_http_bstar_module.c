/*
 * ngx_http_bstar_module.c
 *
 *  Created on: 2017年7月11日
 *      Author: ym
 */

#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>
#include "ngx_bstar.hpp"

typedef struct
{
	ngx_http_upstream_conf_t upstream;
} ngx_http_bstar_t;

struct BSCP_Packet_Plain
{
  short mode;
  short error;
  int plainLength;
  int sequence;
  int command;
};

struct BSCP_Header
{
  char mark[2];
  char version;
  char encoded;
  int length;
  struct BSCP_Packet_Plain packet;
};

#define ngx_log_debug_write(r, info)\
	do {\
		ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "file:%s line:%d warn:%s", __FILE__, __LINE__, info);\
	}while (0)

static void *ngx_http_bstar_create(ngx_conf_t *cf);
static char *ngx_http_bstar_merge(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_bstar_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_bstar_parse(ngx_http_request_t *r);
static void ngx_http_read_buffer(ngx_chain_t *out, ngx_buf_t *buf);

static ngx_int_t ngx_http_bstar_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_bstar_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_bstar_process_header(ngx_http_request_t *r);
static void ngx_http_bstar_abort_request(ngx_http_request_t *r);
static void ngx_http_bstar_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t ngx_http_bstar_input_filter_init(void *data);
static ngx_int_t ngx_http_bstar_input_filter(void *data, ssize_t bytes);

static ngx_command_t ngx_http_bstar_commands[] =
{
		{
				ngx_string("bstar_pass"),
				NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
				ngx_http_bstar_block,
				NGX_HTTP_LOC_CONF_OFFSET,
				0,
				NULL
		},
		ngx_null_command
};

static ngx_http_module_t ngx_http_bstar_module_ctx =
{
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		ngx_http_bstar_create,
		ngx_http_bstar_merge
};

ngx_module_t ngx_http_bstar_module =
{
		NGX_MODULE_V1,
		&ngx_http_bstar_module_ctx,
		ngx_http_bstar_commands,
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

static ngx_int_t ngx_http_bstar_input_filter_init(void *data)
{
    ngx_http_request_t    *r = data;
    ngx_http_upstream_t   *u;

    u = r->upstream;

    if (u->headers_in.content_length_n == 0 || u->headers_in.status_n != NGX_HTTP_OK)
    {
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;
    }
    else
    {
        u->length = u->headers_in.content_length_n;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_bstar_input_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t  *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next)
    {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL)
    {
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

    if (u->length == -1)
    {
        return NGX_OK;
    }

    u->length -= bytes;

    return NGX_OK;
}

static void ngx_http_read_buffer(ngx_chain_t *out, ngx_buf_t *buf)
{
	ngx_chain_t *tout;
	ngx_buf_t *obuf;
	ngx_file_t *file;

	for (tout = out; tout; tout = tout->next)
	{
		obuf = tout->buf;

		if (obuf->in_file)
		{
			file = obuf->file;

			ngx_read_file(file, buf->last, obuf->file_last - obuf->file_pos, obuf->file_pos);
			buf->last += obuf->file_last - obuf->file_pos;
		}
		else
		{
			ngx_memcpy(buf->last, obuf->pos, obuf->last - obuf->pos);
			buf->last += obuf->last - obuf->pos;
		}
	}
}

static ngx_int_t ngx_http_bstar_create_request(ngx_http_request_t *r)
{
	ngx_chain_t *out;
	ngx_buf_t *buf = NULL;
	ngx_buf_t *header;
	struct BSCP_Header *bHeader;
	ngx_http_upstream_t *u = r->upstream;

	header = ngx_create_temp_buf(r->pool, sizeof(struct BSCP_Header));

	if (header == NULL)
	{
		ngx_log_debug_write(r, "no memory.");
		return NGX_ERROR;
	}

	header->last += sizeof(struct BSCP_Header);
	bHeader = (struct BSCP_Header *)header->pos;
	bHeader->mark[0] = 'B';
	bHeader->mark[1] = 'S';

	if (r->method != NGX_HTTP_GET)
	{
		buf = ngx_create_temp_buf(r->pool, r->headers_in.content_length_n);

		if (buf == NULL)
		{
			ngx_log_debug_write(r, "no memory.");
			return NGX_ERROR;
		}

		ngx_http_read_buffer(r->request_body->bufs, buf);
	}

	buf = ngx_bstar_create_request(r, buf, &bHeader->packet.command);

	if (buf == NGX_CONF_ERROR)
	{
		ngx_log_debug_write(r, "process request error.");
		return NGX_ERROR;
	}

	out = ngx_alloc_chain_link(r->pool);

	if (out == NULL)
	{
		ngx_log_debug_write(r, "no memory.");
		return NGX_ERROR;
	}

	out->buf = header;

	bHeader->length = sizeof(bHeader->packet);
	u->request_bufs = out;

	if (buf != NULL)
	{
		bHeader += buf->last - buf->pos;
		out = ngx_alloc_chain_link(r->pool);

		if (out == NULL)
		{
			ngx_log_debug_write(r, "no memory.");
			return NGX_ERROR;
		}
		out->buf = buf;
		u->request_bufs->next = out;
	}

	out->next = NULL;
	return NGX_OK;
}

static ngx_int_t ngx_http_bstar_reinit_request(ngx_http_request_t *r)
{
	return NGX_OK;
}

static ngx_int_t ngx_http_bstar_process_header(ngx_http_request_t *r)
{
	struct BSCP_Header *bHeader;
	ngx_http_upstream_t *u = r->upstream;
	ngx_buf_t *b = &u->buffer;

	if ((size_t)(b->last - b->pos) < sizeof(*bHeader))
	{
		return NGX_AGAIN;
	}

	bHeader = (struct BSCP_Header *)b->pos;
	size_t size = b->end - b->pos;
	size -= sizeof(*bHeader) - sizeof(struct BSCP_Packet_Plain);

	if (size < (size_t)bHeader->length)
	{
		size = sizeof(*bHeader) - sizeof(struct BSCP_Packet_Plain);
		size += bHeader->length;

		b = ngx_create_temp_buf(r->pool, size);

		if (b == NULL)
		{
			ngx_log_debug_write(r, "no memory.");
			return NGX_ERROR;
		}

		ngx_memcpy(b->last, u->buffer.pos, u->buffer.last - u->buffer.pos);
		b->last += u->buffer.last - u->buffer.pos;
		u->buffer = *b;
	}

	size = sizeof(*bHeader) - sizeof(struct BSCP_Packet_Plain);
	size += bHeader->length;

	if ((size_t)(b->last - b->pos) != size)
		return NGX_AGAIN;

	b->pos += sizeof(*bHeader);
	b = ngx_bstar_process_header(r, b);

	if (b == NGX_CONF_ERROR)
	{
		ngx_log_debug_write(r, "create memory error.");
		return NGX_ERROR;
	}

	u->headers_in.status_n = NGX_HTTP_OK;
	u->headers_in.content_length_n = b->last - b->pos;

	return NGX_OK;
}

static void ngx_http_bstar_abort_request(ngx_http_request_t *r)
{

}

static void ngx_http_bstar_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
	ngx_log_debug_write(r, "finalize request.");
}

static ngx_int_t ngx_http_bstar_parse(ngx_http_request_t *r)
{
	ngx_http_upstream_t *u;
	ngx_http_bstar_t *bstar;
	ngx_bstar_ctx_t *ctx;

	if (ngx_http_set_content_type(r) != NGX_OK)
	{
		ngx_log_debug_write(r, "set content error.");
		return NGX_ERROR;
	}

	if (ngx_http_upstream_create(r) != NGX_OK)
	{
		ngx_log_debug_write(r, "create upstream error.");
		return NGX_ERROR;
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_bstar_module);

	if (ctx == NULL)
	{
		ctx = ngx_pcalloc(r->pool, sizeof(*ctx));

		if (ctx == NULL)
		{
			ngx_log_debug_write(r, "no memory.");
			return NGX_ERROR;
		}

		ngx_http_set_ctx(r, ctx, ngx_http_bstar_module);
	}

	ctx->data = ngx_bstar_find(&r->uri);

	if (ctx->data == NULL)
	{
		ngx_log_debug_write(r, "find uri error.");
		return NGX_ERROR;
	}

	bstar = ngx_http_get_module_loc_conf(r, ngx_http_bstar_module);
	u = r->upstream;
	u->conf = &bstar->upstream;
	ngx_str_set(&u->schema, "bstar");
	u->output.tag = (ngx_buf_tag_t)&ngx_http_bstar_module;
	u->conf->buffering = 0;

	u->create_request = ngx_http_bstar_create_request;
	u->reinit_request = ngx_http_bstar_reinit_request;
	u->process_header = ngx_http_bstar_process_header;
	u->abort_request = ngx_http_bstar_abort_request;
	u->finalize_request = ngx_http_bstar_finalize_request;

	u->input_filter_ctx = r;
	u->input_filter_init = ngx_http_bstar_input_filter_init;
	u->input_filter = ngx_http_bstar_input_filter;

	return ngx_http_read_client_request_body(r, ngx_http_upstream_init);
}

static char *ngx_http_bstar_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;
	ngx_http_bstar_t *bstar;
	ngx_str_t *value;
	ngx_url_t u;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	if (clcf->name.data[clcf->name.len - 1] == '/')
		clcf->auto_redirect = 1;

	value = cf->args->elts;
	ngx_memzero(&u, sizeof(u));
	u.url = value[1];
	u.no_resolve = 1;
	bstar = ngx_http_conf_get_module_loc_conf(cf, ngx_http_bstar_module);

	bstar->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);

	if (bstar->upstream.upstream == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "not found upstream");
		return NGX_CONF_ERROR;
	}

	clcf->handler = ngx_http_bstar_parse;

	return NGX_CONF_OK;
}

static void *ngx_http_bstar_create(ngx_conf_t *cf)
{
	ngx_http_bstar_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));

	if (conf == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "no memory.");
		return NULL;
	}

    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.request_buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.force_ranges = NGX_CONF_UNSET;

    conf->upstream.local = NGX_CONF_UNSET_PTR;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

	return conf;
}

static char *ngx_http_bstar_merge(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_bstar_t *prev = parent;
	ngx_http_bstar_t *conf = child;


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
