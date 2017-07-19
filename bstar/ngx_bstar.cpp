/*
 * ngx_bstar.cpp
 *
 *  Created on: 2017年7月11日
 *      Author: ym
 */

#include"ngx_bstar.hpp"

#include <iostream>
#include <map>
#include <string>
#include <pthread.h>
#include <json/json.h>

using namespace std;
using namespace Json;

pthread_once_t once = PTHREAD_ONCE_INIT;

class Manager
{
public:
	Manager(){};
	virtual ~Manager(){};
public:
	virtual int process_request(Json::Value &out, std::string &rbody)
	{
		rbody = out.toStyledString();
		return 0;
	};

	virtual int process_response(std::string &body, Json::Value &rout)
	{
		Reader reader;
		if (body.length() == 0)
			return 0;

		if (!reader.parse(body.c_str(), body.c_str() + body.length(), rout, true))
		{
			return -1;
		}

		return 0;
	};
};

map<string, Manager *> m_map;

void insert_map()
{
	m_map["/"] = new Manager();
}

void *ngx_bstar_find(ngx_str_t *url)
{
	pthread_once(&once, insert_map);
	string path;
	path.append((char *)url->data, url->len);

	map<string, Manager *>::iterator mit = m_map.find(path);

	if (mit == m_map.end())
		return m_map["/"];

	return mit->second;
}

ngx_buf_t *ngx_bstar_create_request(ngx_http_request_t *r, ngx_buf_t *body, int *cmd)
{
	*cmd = 1;
	ngx_buf_t *buf = NULL;
	string data = "";
	Value out;
	ngx_bstar_ctx_t *ctx = (ngx_bstar_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_bstar_module);

	Manager *manager = static_cast<Manager *>(ctx->data);

	if (body != NULL)
	{
		Reader reader;

		if(!reader.parse((char *)body->pos, (char *)body->last, out, true))
		{
			return (ngx_buf_t *)NGX_CONF_ERROR;
		}
	}

	if (manager->process_request(out, data) != NGX_OK)
	{
		return (ngx_buf_t *)NGX_CONF_ERROR;
	}

	if (data.length() > 0)
	{
		buf = ngx_create_temp_buf(r->pool, data.length());

		if (buf == NULL)
		{
			return (ngx_buf_t *)NGX_CONF_ERROR;
		}

		ngx_memcpy(buf->last, data.c_str(), data.length());
		buf->last += data.length();
	}

	return buf;
}

ngx_buf_t *ngx_bstar_process_header(ngx_http_request_t *r, ngx_buf_t *body)
{
	string data;
	Value out;
	if (body == NULL || body->last == body->pos)
		return NULL;

	data.append((char *)body->pos, body->last - body->pos);
	ngx_bstar_ctx_t *ctx = (ngx_bstar_ctx_t *)ngx_http_get_module_ctx(r, ngx_http_bstar_module);

	Manager *manager = static_cast<Manager *>(ctx->data);

	if (manager->process_response(data, out) != NGX_OK)
	{
		return (ngx_buf_t *)NGX_CONF_ERROR;
	}

	body = ngx_create_temp_buf(r->pool, out.toStyledString().length());

	if (body == NULL)
	{
		return (ngx_buf_t *)NGX_CONF_ERROR;
	}

	ngx_memcpy(body->last, out.toStyledString().c_str(), out.toStyledString().length());
	body->last += out.toStyledString().length();
	return body;
}
