# Rust Electerm sync server

A simple rust electerm data sync server.

## Use


```bash
git clone git@github.com:electerm/electerm-sync-server-rust.git
cd electerm-sync-server-rust

# create env file, then edit .env
cp sample.env .env

cargo run

# would show something like
# server running at http://127.0.0.1:7837

# in electerm sync settings, set custom sync server with:
# server url: http://127.0.0.1:7837
# JWT_SECRET: your JWT_SECRET in .env
# JWT_USER_NAME: one JWT_USER in .env
```

## Test

todo

## Write your own data store

Just take [src/file-store.rs](src/file-store.jrs) as an example, write your own read/write method

## License

MIT
