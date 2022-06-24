# 项目介绍
一个简易版本的 socks5 服务端，实现了账号密码的验证方式

## 使用方式
1. 运行 `main.go`
2. 客户端使用 curl，`curl -v --proxy socks5://admin:123456@localhost:8888 www.baidu.com`

## todo
* 接入命令行工具，使之成为一个命令行软件
* 实现 ss5 的客户端
* 实现多层 ss5 代理转发
* 实现 4层负载均衡器
