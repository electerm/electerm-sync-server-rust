use std::env;
mod file_store;
mod web_app;
use actix_web::{middleware::Logger, web, App, HttpServer};
use dotenv::dotenv;
use env_logger::{Builder, Env};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let port = env::var("PORT").expect("no PORT env");
    let host = env::var("HOST").expect("no HOST env");
    // let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET not set");
    println!("running server at http://{}:{}", host, port);
    let env = Env::default().filter_or("MY_LOG_LEVEL", "info");
    Builder::from_env(env).init();
    HttpServer::new(|| {
        App::new()
          .wrap(Logger::default())
          .service(
              web::resource("/sync")
                  .route(web::put().to(file_store::write))
                  .route(web::get().to(file_store::read))
          )
          .service(web::resource("/test").route(web::get().to(web_app::test)))
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
}
