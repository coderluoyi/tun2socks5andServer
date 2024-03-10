# tun2socks_stu

使用方法
- 部署 socks5 服务
  - 使用我的server：将 socks.lua 使用 luajit 编译后放置到 ...openresty/nginx/lua 目录下，并启动 nginx
  - 使用其他人实现的 socks5 server
- 部署 tun2socks5 客户端
  - 修改 main.go 中的参数，之后编译运行
  - 然后运行 wintun 路由引流脚本

目前实现的内容：

- [x] socks5 client power by golang / wireguard_wintun / gvisor_tcpip
  - 功能
    - socks5 代理
    - 透明代理，客户端感受不到自己的流量被 socks 服务器代理
    - 高性能，客户端使用 go 的并发编程，服务端使用  luajit、coroutine 及 nginx 的事件驱动
    - 较完善的错误处理及日志记录
  - 支持的系统
    - [x] windows （目前只支持了 windows）
  - 支持的L4层协议
    - [x] TCP (目前只支持 TCP)
    - [ ] UDP 通过直连 + pipe 的方式实现，不走 socks5，也就是说 UDP目前不支持 socks5 代理
  - 认证方式：目前只支持无密码认证
- [x] socks5 server power by OpenResty
  - 支持的L4层协议
    - [x] TCP (目前只支持 TCP)
  - 认证方式
    - [x] 无密码认证
    后续计划
1. BUG 查缺补漏
2. TLS 握手，加密代理服务器和客户端的认证过程及通信过程
3. 用户密码的认证方式
4. Docker & K8S
5. 适配更多操作系统
6. 