和nginx代码
auth:客户端发出请求， nginx收到请求后，首先发往鉴权服务器一份，然后发往真正处理请求的服务器器
auth_cookie: nginx 本地缓存客户端权限一份， 这个功能依赖客户端是否支持keep-alive
bstar:客户端通过http连接nginx， nginx通过私有协议连接后端服务器， 后端服务器处理完毕后经nginx 发送http到客户端
flv_test:nginx解析flv格式， 通过chunked方式发送数据到客户端
