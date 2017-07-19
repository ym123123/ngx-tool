/*
 * ngx_bstar.hpp
 *
 *  Created on: 2017年7月11日
 *      Author: ym
 */

#ifndef SRC_BSTAR_NGX_BSTAR_HPP_
#define SRC_BSTAR_NGX_BSTAR_HPP_

#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>

typedef struct
{
	void *data;
} ngx_bstar_ctx_t;

extern ngx_module_t ngx_http_bstar_module;


void *ngx_bstar_find(ngx_str_t *url);
ngx_buf_t *ngx_bstar_create_request(ngx_http_request_t *r, ngx_buf_t *body, int *cmd);
ngx_buf_t *ngx_bstar_process_header(ngx_http_request_t *r, ngx_buf_t *body);

#ifdef __cplusplus
}
#endif


#endif /* SRC_BSTAR_NGX_BSTAR_HPP_ */
