/*
 * ngx_http_auth_cookie.c
 *
 *  Created on: 2017年6月9日
 *      Author: ym
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct
{
	ngx_flag_t auth_on;
	ngx_uint_t auth_time;
	ngx_str_t auth_url;
} ngx_http_auth_cookie_t;

typedef struct
{
	time_t time;
	ngx_str_t resp;
	ngx_int_t status;
} ngx_http_auth_t;

static void *ngx_http_auth_cookie_create_loc(ngx_conf_t *cf);
static char *ngx_http_auth_cookie_merge_loc(ngx_conf_t *cf, void *prev, void *conf);
static ngx_int_t ngx_http_auth_cookie_parse(ngx_conf_t *cf);
//static ngx_str_t resp_str = ngx_string("Resp");

static ngx_command_t ngx_http_auth_cookies[] =
{
		{
				ngx_string("auth_url"),
				NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
				ngx_conf_set_str_slot,
				NGX_HTTP_LOC_CONF_OFFSET,
				offsetof(ngx_http_auth_cookie_t, auth_url),
				NULL
		},
		{
				ngx_string("auth_time"),
				NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
				ngx_conf_set_sec_slot,
				NGX_HTTP_LOC_CONF_OFFSET,
				offsetof(ngx_http_auth_cookie_t, auth_time),
				NULL
		},
		{
				ngx_string("auth_on"),
				NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
				ngx_conf_set_flag_slot,
				NGX_HTTP_LOC_CONF_OFFSET,
				offsetof(ngx_http_auth_cookie_t, auth_on),
				NULL
		},
		ngx_null_command
};

static ngx_http_module_t ngx_http_auth_cookie_module_ctx =
{
		NULL,
		ngx_http_auth_cookie_parse,
		NULL,
		NULL,
		NULL,
		NULL,
		ngx_http_auth_cookie_create_loc,
		ngx_http_auth_cookie_merge_loc
};

ngx_module_t ngx_http_auth_cookie_module =
{
		NGX_MODULE_V1,
		&ngx_http_auth_cookie_module_ctx,
		ngx_http_auth_cookies,
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

static void ngx_http_auth_cookie_destroy(void * args)
{

}

static void *ngx_http_get_auth_cookie(ngx_connection_t *conn)
{
	ngx_http_auth_t *auth;
	ngx_pool_cleanup_t *cln = conn->pool->cleanup;

	while (cln)
	{
		if (cln->handler == ngx_http_auth_cookie_destroy)
		{
			return cln->data;
		}

		cln = cln->next;
	}

	cln = ngx_pool_cleanup_add(conn->pool, sizeof(ngx_http_auth_t));

	if (cln == NULL)
	{
		return NULL;
	}

	cln->handler = ngx_http_auth_cookie_destroy;
	auth = cln->data;

	auth->time = 0;
	auth->status = 0;
	ngx_str_set(&auth->resp, "");
	return auth;
}


static ngx_int_t ngx_http_subrequest_post(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
	ngx_http_auth_t *auth = data;

    if (rc < NGX_OK || rc >= NGX_HTTP_SPECIAL_RESPONSE || r->upstream == NULL
    		|| r->upstream->headers_in.status_n >= NGX_HTTP_SPECIAL_RESPONSE)
    {
    	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "subrequest parse uri error.");
    	auth->status = NGX_ERROR;
    	return NGX_DONE;
    }

    auth->time = ngx_time();
    return NGX_OK;
}

static ngx_int_t ngx_http_auth_ip(ngx_http_request_t *r)
{
	ngx_http_auth_cookie_t *cookie;
	ngx_http_request_t *pasr = NULL;
	ngx_http_auth_t *auth;
	ngx_http_post_subrequest_t *post;

	cookie = ngx_http_get_module_loc_conf(r, ngx_http_auth_cookie_module);

	if (cookie->auth_on == 0)
		return NGX_DECLINED;

	auth = ngx_http_get_auth_cookie(r->main->connection);

	if (auth == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no auth.");
		return NGX_ERROR;
	}

	if (auth->status == NGX_ERROR)
	{
		//状态出现问题， 不能再继续向下执行
		r->keepalive = 0;
		return NGX_HTTP_FORBIDDEN;
	}

	if (auth->status == NGX_OK)
	{
		post = ngx_palloc(r->pool, sizeof(*post));
		post->handler = ngx_http_subrequest_post;
		post->data = auth;

		if (ngx_http_subrequest(r, &cookie->auth_url, &r->args,
				&pasr, post,
				NGX_HTTP_SUBREQUEST_IN_MEMORY | NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no subrequest.");
			return NGX_ERROR;
		}

		pasr->headers_in.content_length_n = 0;
		pasr->args_start = r->args_start;
		auth->status = NGX_AGAIN;
		return NGX_AGAIN;
	}

	auth->status = NGX_OK;
	return NGX_DECLINED;
}

static ngx_int_t ngx_http_auth_cookie_parse(ngx_conf_t *cf)
{
	ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	ngx_http_handler_pt *h;

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

	if (h == NULL)
	{
		ngx_log_error(NGX_LOG_WARN, cf->log, 0, "no memory.");
		return NGX_ERROR;
	}

	*h = ngx_http_auth_ip;

	return NGX_OK;
}

static void *ngx_http_auth_cookie_create_loc(ngx_conf_t *cf)
{
	ngx_http_auth_cookie_t *conf = ngx_palloc(cf->pool, sizeof(*conf));

	if (conf == NULL)
	{
		ngx_log_error(NGX_LOG_WARN, cf->log, 0, "create auth_cookie error.");
		return NULL;
	}

	conf->auth_on = NGX_CONF_UNSET;
	conf->auth_time = NGX_CONF_UNSET_UINT;
	conf->auth_url.data = NULL;
	conf->auth_url.len = 0;
	return conf;
}

static char *ngx_http_auth_cookie_merge_loc(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_auth_cookie_t *prev = parent;
	ngx_http_auth_cookie_t *conf = child;

	ngx_conf_merge_off_value(conf->auth_on, prev->auth_on, 0);
	ngx_conf_merge_uint_value(conf->auth_time, prev->auth_time, 60);
	ngx_conf_merge_str_value(conf->auth_url, prev->auth_url, "");

	if (conf->auth_url.len != 0)
	{
		conf->auth_on = 1;
	}

	return NGX_CONF_OK;
}
