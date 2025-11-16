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
    
    // Get number of workers (default to number of CPU cores)
    let workers = env::var("WORKERS")
        .ok()
        .and_then(|w| w.parse::<usize>().ok())
        .unwrap_or_else(num_cpus::get);
    
    let env = Env::default().filter_or("MY_LOG_LEVEL", "info");
    Builder::from_env(env).init();
    
    // Initialize database
    let pool = file_store::init_db()
        .expect("Failed to initialize database");
    
    println!("Database initialized successfully");
    println!("Workers: {}", workers);
    
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "NOT_SET".to_string());
    let jwt_users = env::var("JWT_USERS").unwrap_or_else(|_| "NOT_SET".to_string());
    
    println!("\n========================================");
    println!("🚀 Server running at http://{}:{}", host, port);
    println!("========================================\n");
    
    println!("📝 Configuration Guide:");
    println!("----------------------------------------");
    println!("In electerm sync settings, set custom sync server with:\n");
    println!("  API URL:    http://{}:{}/api/sync\n", host, port);
    
    println!("🔐 Authentication:");
    println!("----------------------------------------");
    println!("  JWT_SECRET:    {}", if jwt_secret == "NOT_SET" { "⚠️  NOT SET" } else { &jwt_secret });
    println!("  JWT_USERS:     {}", if jwt_users == "NOT_SET" { "⚠️  NOT SET" } else { &jwt_users });
    println!("========================================\n");

    HttpServer::new(move || {
        let auth = HttpAuthentication::bearer(jwt_middleware);
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(Logger::default())
            .service(
                web::resource("/api/sync")
                    .wrap(auth)
                    .route(web::put().to(file_store::write))
                    .route(web::get().to(file_store::read))
                    .route(web::post().to(file_store::test))
            )
            .service(web::resource("/test").route(web::get().to(web_app::test)))
    })
    .workers(workers)
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
}