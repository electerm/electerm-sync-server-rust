[English](README.md)

# Electerm 同步服务器 Rust 版

开源终端/ssh/telnet/serialport/RDP/VNC/Spice/sftp/ftp客户端(Linux, Mac, Windows, Android, HarmonyOS)。

除了主流的 Windows/macOS/Linux/Android，electerm 还支持鸿蒙(HarmonyOS)，以及老旧系统——如 Ubuntu 18、Windows 7、macOS 10+，以及国产特殊 Linux 发行版如 UOS、麒麟(Kylin)、龙芯(LoongArch，含旧世界与新世界)。

<p>
  <a href="https://electerm.org">主页 / 下载</a> ·
  <a href="https://theme.electerm.org">主题</a> ·
  <a href="https://github.com/electerm/electerm-web-docker">Docker</a> ·
  <a href="https://demo.electerm.org">在线演示</a> ·
  <a href="https://github.com/electerm/electerm-android">Android</a> ·
  <a href="https://github.com/electerm/electerm-harmony">鸿蒙</a> ·
  <a href="https://appgallery.huawei.com/app/detail?id=org.electerm.electerm">华为应用市场</a> ·
  <a href="https://www.microsoft.com/store/apps/9NCN7272GTFF">微软商店</a> ·
  <a href="https://snapcraft.io/electerm">Snap 商店</a> ·
  <a href="https://repos.electerm.org/deb">deb 仓库</a> ·
  <a href="https://repos.electerm.org/rpm">rpm 仓库</a>
</p>

<div>🌐 <strong><a href="https://cloud.electerm.org">electerm 在线版</a></strong> — 公共免费在线 electerm 应用</div>
<div>🤖 <strong><a href="https://ai.electerm.org">electerm AI</a></strong> — 免费为 electerm 用户提供 AI</div>
<div>💻 <strong><a href="https://github.com/electerm/electerm-web">electerm-web</a></strong> — 运行于浏览器(支持移动设备)的 web app 版本</div>

[![Build Status](https://github.com/electerm/electerm-sync-server-rust/actions/workflows/linux.yml/badge.svg)](https://github.com/electerm/electerm-sync-server-rust/actions)

一个简单的 Rust Electerm 数据同步服务器。

## 使用

```bash
git clone git@github.com:electerm/electerm-sync-server-rust.git
cd electerm-sync-server-rust

# 创建环境文件，然后编辑 .env
cp sample.env .env

cargo run

# 会显示类似内容
# server running at http://127.0.0.1:7837

# 在 electerm 同步设置中，设置自定义同步服务器：
# 服务器 URL: http://127.0.0.1:7837
# 然后你可以在 electerm 自定义同步中使用 http://127.0.0.1:7837/api/sync 作为 API URL

# JWT_SECRET: .env 中的 JWT_SECRET
# JWT_USER_NAME: .env 中的一个 JWT_USER
```

## 生产运行

`cargo run` 以调试模式运行服务器。对于生产部署：

```bash
# 构建优化的发布二进制文件
cargo build --release

# 运行生产二进制文件
./target/release/electerm-sync-rust-server
```

## 测试

```sh
cargo test -- --test-threads=1
```

## 编写自己的数据存储

只需以 [src/file_store.rs](src/file_store.rs) 为例，编写自己的读写方法

## 其他语言的同步服务器

[https://github.com/electerm/electerm/wiki/Custom-sync-server](https://github.com/electerm/electerm/wiki/Custom-sync-server)

## 许可证

MIT


