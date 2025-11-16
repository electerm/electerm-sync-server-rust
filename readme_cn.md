[English](README.md)

# Electerm 同步服务器 Rust 版

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


