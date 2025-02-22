use actix_web::{web, HttpResponse, HttpRequest, HttpMessage};
use std::env;
use std::fs::File;
use std::io::Write;
use serde_json::Value;
use std::io::Read;

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

fn create_file_path(user_id: &str) -> String {
    let mut file_path = get_env("FILE_STORE_PATH", Some(&get_cwd_string()));
    file_path.push_str("/");
    file_path.push_str(user_id);
    file_path.push_str(".json");
    file_path
}

pub async fn write(req: HttpRequest, json_data: web::Json<Value>) -> HttpResponse {
    let user_id = req.extensions().get::<String>().unwrap().clone();
    let file_path = create_file_path(&user_id);

    let mut file = File::create(file_path).expect("Unable to create file");
    let json_string = serde_json::to_string(&json_data).expect("Unable to serialize JSON");
    file.write_all(json_string.as_bytes()).expect("Unable to write data to file");

    HttpResponse::Ok().body("ok")
}

pub async fn read(req: HttpRequest) -> HttpResponse {
    let user_id = req.extensions().get::<String>().unwrap().clone();
    let file_path = create_file_path(&user_id);
    
    match File::open(file_path) {
        Ok(mut file) => {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                // Add type annotation here
                if let Ok(json_data) = serde_json::from_str::<Value>(&contents) {
                    HttpResponse::Ok().json(json_data)
                } else {
                    HttpResponse::InternalServerError().body("Unable to parse JSON")
                }
            } else {
                HttpResponse::InternalServerError().body("Unable to read file")
            }
        }
        Err(_) => HttpResponse::NotFound().body("File not found")
    }
}

pub async fn test(req: HttpRequest) -> HttpResponse {
    let user_id = req.extensions().get::<String>().unwrap().clone();
    HttpResponse::Ok().body(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use actix_web::web::Json;
    use std::fs;
    use serde_json::json;
    use actix_web::body::to_bytes;

    fn setup() {
        env::set_var("FILE_STORE_PATH", env::temp_dir().to_str().unwrap());
    }

    fn cleanup(user_id: &str) {
        let file_path = create_file_path(user_id);
        if fs::metadata(&file_path).is_ok() {
            fs::remove_file(file_path).unwrap();
        }
    }

    #[actix_rt::test]
    async fn test_write_and_read() {
        setup();
        let user_id = "test_user";
        cleanup(user_id);

        // Test write
        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());

        let json_data = Json(json!({"key": "value"}));
        let resp = write(req, json_data).await;
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "ok");

        // Test read
        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());

        let resp = read(req).await;
        assert_eq!(resp.status(), 200);
        
        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, json!({"key": "value"}));

        cleanup(user_id);
    }

    #[actix_rt::test]
    async fn test_read_non_existent_file() {
        setup();
        let user_id = "non_existent_user";
        cleanup(user_id);

        let req = test::TestRequest::default()
            .to_http_request();
        req.extensions_mut().insert(user_id.to_string());

        let resp = read(req).await;
        assert_eq!(resp.status(), 404);
        
        let body = to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "File not found");
    }
}