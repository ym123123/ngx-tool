/*
 * ngx_http_flv_test_module.c
 *
 *  Created on: 2017年7月12日
 *      Author: ym
 */

#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>

static char *ngx_http_flv_test_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_flv_test_parse(ngx_http_request_t *r);

static void ngx_http_flv_handler(ngx_http_request_t *r);

static u_char  ngx_flv_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";

typedef struct
{
	ngx_file_t file;
} flv_ctx_t;

typedef struct
{
  uint8_t header[3];
  uint8_t version;
  uint8_t reserved:5;
  uint8_t audio:1;
  uint8_t tReserved:1;
  uint8_t video:1;
  uint8_t dataOff[4];
} flv_header_t;

typedef struct
{
  uint8_t type;
  uint8_t size[3];
  uint8_t time[3];
  uint8_t timeExtend;
  uint8_t streamId[3];
} flv_tag_t;

static ngx_command_t ngx_http_flv_test_commands[] =
{
		{
				ngx_string("flv_test"),
				NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
				ngx_http_flv_test_block,
				NGX_HTTP_LOC_CONF_OFFSET,
				0,
				NULL
		},
		ngx_null_command
};

static ngx_http_module_t ngx_http_flv_test_ctx =
{
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
};

ngx_module_t ngx_http_flv_test_module =
{
		NGX_MODULE_V1,
		&ngx_http_flv_test_ctx,
		ngx_http_flv_test_commands,
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

static ngx_int_t get_length(u_char *data, size_t size)
{
  ngx_int_t r = 0;
  size_t i;
  for (i=0; i<size; i++)
      r |= (*(data+i) << (((size-1)*8)-8*i));
  return r;
}


static void ngx_http_flv_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_chain_t *out;
	ngx_buf_t *buf;
	flv_ctx_t *ctx;
	flv_tag_t tag;
	ngx_file_t *file;

	ctx = ngx_http_get_module_ctx(r, ngx_http_flv_test_module);
	file = &ctx->file;

	printf("===================\n");
	while (ngx_read_file(file, (u_char *)&tag, sizeof(tag), file->offset) == sizeof(tag))
	{
		ngx_int_t len = get_length(tag.size, sizeof(tag.size)) + sizeof(tag) + 4;
		buf = ngx_create_temp_buf(r->pool, len);
		out = ngx_alloc_chain_link(r->pool);

		if (buf == NULL || out == NULL)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no memory.");
			ngx_http_finalize_request(r, NGX_ERROR);
			return;
		}

		ngx_memcpy(buf->last, (u_char *)&tag, sizeof(tag));
		ngx_read_file(file, buf->last + sizeof(tag), len - sizeof(tag), file->offset);
		buf->last += len;

		out->buf = buf;
		out->next = NULL;
		rc = ngx_http_output_filter(r, out);

		if (rc != NGX_OK)
		{
			if (rc == NGX_AGAIN)
			{
				ngx_handle_write_event(r->connection->write, 0);
				return;
			}
			ngx_http_finalize_request(r, rc);
			return;
		}
	}

	printf("over over over!\n");

	//结束
	ngx_http_finalize_request(r, NGX_DONE);
	return;
}

static ngx_int_t ngx_http_flv_test_parse(ngx_http_request_t *r)
{
	flv_ctx_t *ctx;
	ngx_int_t rc;
	ngx_buf_t *buf;
	ngx_chain_t out;

	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK)
	{
		return rc;
	}

	printf("===========#=========\n");

	ctx = ngx_http_get_module_ctx(r, ngx_http_flv_test_module);

	if (ctx == NULL)
	{
		ngx_http_cleanup_t *cln;
		ngx_pool_cleanup_file_t *file;
		ctx = ngx_pcalloc(r->pool, sizeof(*ctx));

		cln = ngx_http_cleanup_add(r, sizeof(ngx_pool_cleanup_file_t));

		if (ctx == NULL || cln == NULL)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no memory.");
			return NGX_ERROR;
		}

		ctx->file.log = r->connection->log;
		ctx->file.fd = ngx_open_file("/opt/share/src/a.flv", NGX_FILE_RDONLY, NGX_FILE_CREATE_OR_OPEN,
				NGX_FILE_DEFAULT_ACCESS);

		if (ctx->file.fd == NGX_INVALID_FILE)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no found file");
			return NGX_ERROR;
		}

		ngx_file_info("/opt/share/src/a.flv", &ctx->file.info);
		ctx->file.offset += sizeof(ngx_flv_header) - 1 + sizeof(flv_tag_t) + 609 + 4;

		file = cln->data;
		file->log = r->connection->log;
		file->fd = ctx->file.fd;

		cln->handler = ngx_pool_cleanup_file;

		ngx_http_set_ctx(r, ctx, ngx_http_flv_test_module);
	}

	buf = ngx_pcalloc(r->pool, sizeof(*buf));

	if (buf == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no memory.");
		return NGX_ERROR;
	}

	buf->temporary = 1;
	buf->pos = buf->start = ngx_flv_header;
	buf->last = buf->end = ngx_flv_header + sizeof(ngx_flv_header) - 1;

	r->headers_out.content_length_n = -1;
	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "video/x-flv");

	rc = ngx_http_send_header(r);

	if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE)
		return rc;

	r->main->count++;
	out.buf = buf;
	out.next = NULL;

	ngx_http_output_filter(r, &out);
	r->write_event_handler = ngx_http_flv_handler;
	r->write_event_handler(r);

	return NGX_DONE;
}

static char *ngx_http_flv_test_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	if (clcf->name.data[clcf->name.len - 1] == '/')
		clcf->auto_redirect = 1;

	clcf->handler = ngx_http_flv_test_parse;
	return NGX_CONF_OK;
}
