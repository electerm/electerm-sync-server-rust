use std::env;
mod file_store;
mod web_app;
mod jwt_middleware;
use actix_web::{middleware::Logger, web, App, HttpServer};
use actix_web_httpauth::middleware::HttpAuthentication;
use dotenv::dotenv;
use env_logger::{Builder, Env};
use jwt_middleware::jwt_middleware;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let port = env::var("PORT").expect("no PORT env");
    let host = env::var("HOST").expect("no HOST env");
    println!("running server at http://{}:{}", host, port);

    let env = Env::default().filter_or("MY_LOG_LEVEL", "info");
    Builder::from_env(env).init();

    HttpServer::new(|| {
        let auth = HttpAuthentication::bearer(jwt_middleware);
        App::new()
            .wrap(Logger::default())
            .service(
                web::resource("/api/sync")
                    .wrap(auth)
                    .route(web::put().to(file_store::write))
                    .route(web::get().to(file_store::read))
                    .route(web::post().to(web_app::test))
            )
            .service(web::resource("/test").route(web::get().to(web_app::test)))
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
}