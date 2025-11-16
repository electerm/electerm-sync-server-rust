use actix_web::{web, HttpResponse, HttpRequest, HttpMessage};
use std::env;
use serde_json::Value;
use rusqlite::{params, OptionalExtension};
use r2d2_sqlite::SqliteConnectionManager;
use r2d2::Pool;

pub type DbPool = Pool<SqliteConnectionManager>;

fn get_env(key: &str, default_value: Option<&str>) -> String {
    let def = default_value.unwrap_or("").to_string();
    env::var(key).unwrap_or(def)
}

fn get_cwd_string() -> String {
    env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_default()
}

fn get_db_path() -> String {
    let mut db_path = get_env("DATABASE_PATH", Some(&get_cwd_string()));
    if !db_path.ends_with('/') && !db_path.is_empty() {
        db_path.push('/');
    }
    db_path.push_str("electerm_sync.db");
    db_path
}

/// Initialize the database and create tables if they don't exist
pub fn init_db() -> Result<DbPool, rusqlite::Error> {
    let db_path = get_db_path();
    let manager = SqliteConnectionManager::file(&db_path);
    let pool = Pool::new(manager).map_err(|e| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(e))
    })?;
    
    let conn = pool.get().map_err(|e| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(e))
    })?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_data (
            user_id TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;
    
    // Create index on updated_at for potential future queries
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_updated_at ON user_data(updated_at)",
        [],
    )?;
    
    Ok(pool)
}

fn sanitize_user_id(user_id: &str) -> Result<String, String> {
    // Remove any path traversal attempts and special characters
    if user_id.is_empty() || user_id.len() > 100 {
        return Err("Invalid user_id length".to_string());
    }
    
    // Only allow alphanumeric characters, underscore, and hyphen
    if !user_id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err("Invalid user_id characters".to_string());
    }
    
    // Reject path traversal attempts
    if user_id.contains("..") || user_id.contains('/') || user_id.contains('\\') {
        return Err("Invalid user_id format".to_string());
    }
    
    Ok(user_id.to_string())
}

pub async fn write(
    req: HttpRequest,
    json_data: web::Json<Value>,
    pool: web::Data<DbPool>,
) -> HttpResponse {
    let user_id = match req.extensions().get::<String>() {
        Some(id) => id.clone(),
        None => return HttpResponse::Unauthorized().body("User ID not found"),
    };
    
    let sanitized_id = match sanitize_user_id(&user_id) {
        Ok(id) => id,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid user ID: {}", e)),
    };

    let json_string = match serde_json::to_string(&json_data.into_inner()) {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Unable to serialize JSON: {}", e)),
    };
    
    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Database connection error: {}", e)),
    };
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    match conn.execute(
        "INSERT INTO user_data (user_id, data, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id) DO UPDATE SET data = ?2, updated_at = ?3",
        params![sanitized_id, json_string, timestamp],
    ) {
        Ok(_) => HttpResponse::Ok().body("ok"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Unable to write data: {}", e)),
    }
}

pub async fn read(req: HttpRequest, pool: web::Data<DbPool>) -> HttpResponse {
    let user_id = match req.extensions().get::<String>() {
        Some(id) => id.clone(),
        None => return HttpResponse::Unauthorized().body("User ID not found"),
    };
    
    let sanitized_id = match sanitize_user_id(&user_id) {
        Ok(id) => id,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid user ID: {}", e)),
    };
    
    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Database connection error: {}", e)),
    };
    
    match conn.query_row(
        "SELECT data FROM user_data WHERE user_id = ?1",
        params![sanitized_id],
        |row| row.get::<_, String>(0),
    ).optional() {
        Ok(Some(json_string)) => {
            match serde_json::from_str::<Value>(&json_string) {
                Ok(json_data) => HttpResponse::Ok().json(json_data),
                Err(e) => HttpResponse::InternalServerError().body(format!("Unable to parse JSON: {}", e)),
            }
        }
        Ok(None) => HttpResponse::NotFound().body("Data not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

pub async fn test(req: HttpRequest) -> HttpResponse {
    let user_id = match req.extensions().get::<String>() {
        Some(id) => id.clone(),
        None => return HttpResponse::Unauthorized().body("User ID not found"),
    };
    HttpResponse::Ok().body(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use actix_web::web::{Json, Data};
    use serde_json::json;
    use actix_web::body::to_bytes;

    fn setup_test_db() -> DbPool {
        // Use in-memory database for tests
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::new(manager).unwrap();
        
        let conn = pool.get().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_data (
                user_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        ).unwrap();
        
        pool
    }

    fn cleanup(pool: &DbPool, user_id: &str) {
        if let Ok(conn) = pool.get() {
            let _ = conn.execute("DELETE FROM user_data WHERE user_id = ?1", params![user_id]);
        }
    }

    #[actix_rt::test]
    async fn test_write_and_read() {
        let pool = setup_test_db();
        let user_id = "test_user";
        cleanup(&pool, user_id);

        // Test write
        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());

        let json_data = Json(json!({"key": "value"}));
        let resp = write(req, json_data, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "ok");

        // Test read
        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());

        let resp = read(req, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 200);
        
        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, json!({"key": "value"}));

        cleanup(&pool, user_id);
    }

    #[actix_rt::test]
    async fn test_read_non_existent_data() {
        let pool = setup_test_db();
        let user_id = "non_existent_user";
        cleanup(&pool, user_id);

        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());

        let resp = read(req, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 404);
        
        let body = to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "Data not found");
    }

    #[actix_rt::test]
    async fn test_sanitize_user_id_valid() {
        assert!(sanitize_user_id("valid_user123").is_ok());
        assert!(sanitize_user_id("user-name").is_ok());
        assert!(sanitize_user_id("User_123-test").is_ok());
    }

    #[actix_rt::test]
    async fn test_sanitize_user_id_invalid_path_traversal() {
        assert!(sanitize_user_id("../etc/passwd").is_err());
        assert!(sanitize_user_id("..").is_err());
        assert!(sanitize_user_id("user/../admin").is_err());
        assert!(sanitize_user_id("user/admin").is_err());
        assert!(sanitize_user_id("user\\admin").is_err());
    }

    #[actix_rt::test]
    async fn test_sanitize_user_id_invalid_characters() {
        assert!(sanitize_user_id("user@example.com").is_err());
        assert!(sanitize_user_id("user name").is_err());
        assert!(sanitize_user_id("user$name").is_err());
        assert!(sanitize_user_id("user;name").is_err());
    }

    #[actix_rt::test]
    async fn test_sanitize_user_id_invalid_length() {
        assert!(sanitize_user_id("").is_err());
        let long_id = "a".repeat(101);
        assert!(sanitize_user_id(&long_id).is_err());
    }

    #[actix_rt::test]
    async fn test_write_invalid_user_id() {
        let pool = setup_test_db();
        let user_id = "../malicious";

        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());

        let json_data = Json(json!({"key": "value"}));
        let resp = write(req, json_data, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 400);
        
        let body = to_bytes(resp.into_body()).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Invalid user ID"));
    }

    #[actix_rt::test]
    async fn test_read_invalid_user_id() {
        let pool = setup_test_db();
        let user_id = "user/admin";

        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());

        let resp = read(req, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 400);
        
        let body = to_bytes(resp.into_body()).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Invalid user ID"));
    }

    #[actix_rt::test]
    async fn test_write_without_user_id() {
        let pool = setup_test_db();
        let req = test::TestRequest::default()
            .to_http_request();
        // Intentionally not inserting user_id

        let json_data = Json(json!({"key": "value"}));
        let resp = write(req, json_data, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 401);
        
        let body = to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "User ID not found");
    }

    #[actix_rt::test]
    async fn test_read_without_user_id() {
        let pool = setup_test_db();
        let req = test::TestRequest::default()
            .to_http_request();
        // Intentionally not inserting user_id

        let resp = read(req, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 401);
        
        let body = to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "User ID not found");
    }

    #[actix_rt::test]
    async fn test_write_large_json() {
        let pool = setup_test_db();
        let user_id = "large_data_user";
        cleanup(&pool, user_id);

        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());

        // Create a large JSON object
        let mut large_object = serde_json::Map::new();
        for i in 0..1000 {
            large_object.insert(format!("key_{}", i), json!(format!("value_{}", i)));
        }
        let json_data = Json(json!(large_object));
        
        let resp = write(req, json_data, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 200);

        // Verify it can be read back
        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());
        
        let resp = read(req, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 200);

        cleanup(&pool, user_id);
    }

    #[actix_rt::test]
    async fn test_overwrite_existing_data() {
        let pool = setup_test_db();
        let user_id = "overwrite_user";
        cleanup(&pool, user_id);

        // Write first data
        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());
        let json_data = Json(json!({"key": "original"}));
        let resp = write(req, json_data, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 200);

        // Overwrite with new data
        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());
        let json_data = Json(json!({"key": "updated"}));
        let resp = write(req, json_data, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 200);

        // Read and verify it's updated
        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());
        let resp = read(req, Data::new(pool.clone())).await;
        assert_eq!(resp.status(), 200);
        
        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, json!({"key": "updated"}));

        cleanup(&pool, user_id);
    }
}