/*
 * ngx_http_auth_module.c
 *
 *  Created on: 2017年7月14日
 *      Author: root
 */

#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>


typedef struct
{
	ngx_str_t auth_url;
} ngx_http_auth_t;


typedef struct
{
	ngx_flag_t auth;
} ngx_http_auth_ctx_t;

static void *ngx_http_auth_create_loc(ngx_conf_t *cf);
static char *ngx_http_auth_merge_loc(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_auth_post_loc(ngx_conf_t *cf);

static ngx_int_t ngx_http_auth_parse(ngx_http_request_t *r);

static ngx_command_t ngx_http_auth_commands[] =
{
		{
				ngx_string("auth_url"),
				NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				NGX_HTTP_LOC_CONF_OFFSET,
				offsetof(ngx_http_auth_t, auth_url),
				NULL
		},
		ngx_null_command
};

static ngx_http_module_t ngx_http_auth_module_ctx =
{
		NULL,
		ngx_http_auth_post_loc,
		NULL,
		NULL,
		NULL,
		NULL,
		ngx_http_auth_create_loc,
		ngx_http_auth_merge_loc
};

ngx_module_t ngx_http_auth_module =
{
		NGX_MODULE_V1,
		&ngx_http_auth_module_ctx,
		ngx_http_auth_commands,
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

static ngx_int_t ngx_http_auth_block(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
	ngx_http_auth_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_auth_module);

	if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE || r->upstream == NULL
			|| r->upstream->headers_in.status_n >= NGX_HTTP_SPECIAL_RESPONSE)
	{
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "subrequest error:%d", (int)rc);
		ctx->auth = -1;
		return NGX_OK;
	}

	ctx->auth = 2;
	return NGX_OK;
}

static ngx_int_t ngx_http_auth_parse(ngx_http_request_t *r)
{
	ngx_http_auth_ctx_t *ctx;
	ngx_http_auth_t *conf;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_module);

	if (conf->auth_url.len == 0)
	{
		return NGX_DECLINED;
	}

	printf("read read read read read!!!!!\n");
	ctx = ngx_http_get_module_ctx(r, ngx_http_auth_module);

	if (ctx == NULL)
	{
		ctx = ngx_pcalloc(r->pool, sizeof(*ctx));

		if (ctx == NULL)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no memory.");
			return NGX_HTTP_NOT_FOUND;
		}

		ngx_http_set_ctx(r, ctx, ngx_http_auth_module);
	}

	if (ctx->auth == NGX_OK)
	{
		ngx_http_request_t *psr;
		ngx_str_t url;
		ngx_http_post_subrequest_t *sub;

		sub = ngx_palloc(r->pool, sizeof(*sub));

		if (sub == NULL)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no memory.");
			return NGX_HTTP_NOT_FOUND;
		}

		sub->handler = ngx_http_auth_block;

		url.len = conf->auth_url.len + r->uri.len;
		url.data = ngx_palloc(r->pool, url.len);

		if (url.data == NULL)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no memory.");
			return NGX_HTTP_NOT_FOUND;
		}

		ngx_snprintf(url.data, url.len, "%s%s", conf->auth_url.data, r->uri.data);

		if (ngx_http_subrequest(r, &url, &r->args, &psr, sub,
				NGX_HTTP_SUBREQUEST_IN_MEMORY|NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no memory.");
			return NGX_HTTP_NOT_FOUND;
		}

		psr->method = NGX_HTTP_GET;
		psr->headers_in.content_length_n = 0;
		ctx->auth = 1;
		ngx_http_set_ctx(psr, ctx, ngx_http_auth_module);

		return NGX_DONE;
	}

	if (ctx->auth == 2)
		return NGX_DECLINED;
	else if (ctx->auth == 1)
		return NGX_DONE;

	return NGX_HTTP_FORBIDDEN;
}

static ngx_int_t ngx_http_auth_post_loc(ngx_conf_t *cf)
{
	ngx_http_core_main_conf_t *cmcf;
	ngx_http_handler_pt *h;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);


	if (h == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, cf->log, 0, "create handler error.");
		return NGX_ERROR;
	}

	*h = ngx_http_auth_parse;
	return NGX_OK;
}

static void *ngx_http_auth_create_loc(ngx_conf_t *cf)
{
	ngx_http_auth_t *conf = ngx_palloc(cf->pool, sizeof(*conf));

	if (conf == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "no memory.");
		return NULL;
	}

	conf->auth_url.data = NULL;
	return conf;
}

static char *ngx_http_auth_merge_loc(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_auth_t *prev = parent;
	ngx_http_auth_t *conf = child;


	ngx_conf_merge_str_value(conf->auth_url, prev->auth_url, "/auth");
	return NGX_CONF_OK;
}
