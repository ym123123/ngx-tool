#编译
./configure --add-module=src/redis --add-module=src/ngx_http_redis_module --with-ld-opt="-lhiredis"

ngx_http_redis_module：只支持一次性获取数据， 不支持订阅发布这种需要长连功能的应用
依赖ngx_redis模块