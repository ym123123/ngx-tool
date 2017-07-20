/*
 * ngx_redis.h
 *
 *  Created on: 2017年7月19日
 *      Author: ym
 */

#ifndef SRC_REDIS_NGX_REDIS_H_
#define SRC_REDIS_NGX_REDIS_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <hiredis/hiredis.h>
struct redisReader;
typedef redisReader ngx_redis_ctx_t;

typedef struct redisReply ngx_redis_reply_t;
//生成redis reader
ngx_redis_ctx_t *ngx_redis_create_reader();
//销毁redis reader， 请求成功一次必须销毁， 不然存在内存泄露！！！！
void ngx_redis_destroy_reader(ngx_redis_ctx_t *reader);
//得到发送给redis的数据
ngx_buf_t *ngx_redis_command(ngx_pool_t *pool, ngx_array_t *cmd);
/*
 * @params reader: create_reader
 * @params buf: read redis data
 * @params reply: get redis reply
 *
 * @return : ngx_error error.
 * 			ngx_again agin
 * 			ngx_ok get reply
 */
ngx_int_t ngx_redis_parse_data(ngx_redis_ctx_t *reader, ngx_buf_t *buf, ngx_redis_reply_t **reply);


#ifdef __cplusplus
}
#endif

#endif /* SRC_REDIS_NGX_REDIS_H_ */
