#编译
./configure --add-module=src/redis --with-ld-opt="-lhiredis"

ngx_redis nginx直接操作redis,使用官方redis库，redis官方库内部多次自定义malloc， 并没有用到nginx的内存池，在内存分配上redis效率比较低， 需要添加jemalloc库
支持所有的redis命令