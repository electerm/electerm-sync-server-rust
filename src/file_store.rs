use actix_web::{web, HttpResponse, HttpRequest};
use std::env;
use std::fs::File;
use std::io::Write;
use serde_json::Value;
use std::io::Read;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    id: String,
}

fn get_env (key: String, default_value: Option<String>) -> String {
    let def = default_value.unwrap_or(String::new());
    let str = match env::var(key) {
        Ok(str) => str,
        Err(_) => return def,
    };
    str
}

fn get_cwd_string() -> String {
    match env::current_dir() {
        Ok(cwd) => {
            if let Some(path) = cwd.to_str() {
                return path.to_string();
            }
        }
        Err(_) => {}
    }
    String::new()
}

fn create_file_path (user_id: String) -> String {
    // let mut file_path = match env::var("FILE_STORE_PATH") {
    //     Ok(file_path) => file_path,
    //     Err(_) => return get_cwd_string(),
    // };
    let mut file_path = get_env(String::from("FILE_STORE_PATH"), Some(get_cwd_string()));
    file_path.push_str("/");
    file_path.push_str(&user_id);
    file_path.push_str(".json");
    file_path
}

fn check_jwt(req: &HttpRequest) -> Result<String, HttpResponse> {
    let auth_header = req.headers().get("Authorization");
    let token = match auth_header {
        Some(header_value) => {
            let header_str = header_value.to_str().unwrap();
            if header_str.starts_with("Bearer") {
                header_str[7..].trim()
            } else {
                return Err(HttpResponse::Unauthorized()
                    .body("Invalid Authorization header"))
            }
        },
        None => {
            return Err(HttpResponse::Unauthorized()
                .body("Missing Authorization header"))
        }
    };
    let jwt_secret = get_env(String::from("JWT_SECRET"), None);// env::var("JWT_SECRET").expect("JWT_SECRET not set");
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let mut validation = Validation::default();
    validation.algorithms = vec![Algorithm::HS256];
    validation.validate_exp = false;
    let token_data = decode::<Claims>(&token, &decoding_key, &validation);
    match token_data {
        Ok(token_data) => {
            let user_ids_str = get_env(String::from("JWT_USERS"), None); //env::var("JWT_USERS").expect("USER_IDS not set");
            let user_ids: Vec<&str> = user_ids_str.split(',').collect();
            let id = token_data.claims.id.as_str();
            if user_ids.contains(&id) {
                Ok(id.to_string())
            } else {
                Err(HttpResponse::Unauthorized()
                    .body("Invalid user ID"))
            }
        },
        Err(err) => {
            Err(HttpResponse::Unauthorized()
                .body(format!("Invalid token: {}", err)))
        }
    }
}

pub async fn write (req: HttpRequest, json_data: web::Json<Value>) -> HttpResponse {
    let user_id = match check_jwt(&req) {
        Ok(user_id) => user_id,
        Err(resp) => return resp
    };
    let file_path = create_file_path(user_id);
    let mut file = File::create(file_path).expect("Unable to create file");
    let json_string = serde_json::to_string(&json_data).expect("Unable to serialize JSON");
    file.write_all(json_string.as_bytes())
        .expect("Unable to write data to file");

    HttpResponse::Ok().body("ok")
}

pub async fn read (req: HttpRequest) -> HttpResponse {
    let user_id = match check_jwt(&req) {
        Ok(user_id) => user_id,
        Err(resp) => return resp
    };
    let file_path = create_file_path(user_id);
    let mut file = File::open(file_path).expect("Unable to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Unable to read file");

    let json_data: Value = serde_json::from_str(&contents).expect("Unable to parse JSON");

    HttpResponse::Ok().json(json_data)
}
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App, http::StatusCode};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use chrono::{Utc, Duration};
    use dotenv::dotenv;

    fn create_jwt_authorization_header() -> String {
        let jwt_secret = get_env(String::from("JWT_SECRET"), None);

        let user_ids_str = get_env(String::from("JWT_USERS"), None);
    
        let user_ids: Vec<&str> = user_ids_str.split(',').collect();
        let user_id = user_ids.first().unwrap_or(&"").to_string();
    
        let expiration = Utc::now() + Duration::seconds(999);
    
        let claims = Claims {
            id: user_id,
            exp: expiration.timestamp() as usize,
        };
    
        let jwt_token = match encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        ) {
            Ok(token) => token,
            Err(_) => return String::new(),
        };
    
        format!("Bearer {}", jwt_token)
    }


    // #[actix_rt::test]
    async fn test_write_endpoint() {
        dotenv().ok();
        // Create a test app
        let app = App::new()
            .route("/write", web::post().to(write));

        // Create a test request
        let mut app = test::init_service(app).await;
        let req = test::TestRequest::post()
            .uri("/write")
            .insert_header(("Authorization", create_jwt_authorization_header()))
            .set_json(&serde_json::json!({ "key": "value" }))
            .to_request();

        // Send the test request
        let response = test::call_service(&mut app, req).await;

        // Assert the response
        assert_eq!(response.status(), StatusCode::OK);
        
        // Extract the response body
        let response_body = test::read_body(response).await;
        
        // Convert the response body to a string (if applicable)
        let response_body_str = String::from_utf8(response_body.to_vec()).unwrap();
        
        assert_eq!(response_body_str, "ok");

        let req1 = test::TestRequest::post()
        .uri("/write")
        .insert_header(("Authorization", "ggg"))
        .set_json(&serde_json::json!({ "key": "value" }))
        .to_request();
        // Send the test request
        let response1 = test::call_service(&mut app, req1).await;

        // Assert the response
        assert_eq!(response1.status(), StatusCode::UNAUTHORIZED);
        // Add more assertions if needed
    }


    async fn test_read_endpoint() {
        dotenv().ok();
        // Create a test app
        let app = App::new()
            .route("/read", web::get().to(read));

        // Create a test request
        let mut app = test::init_service(app).await;
        let req = test::TestRequest::get()
            .uri("/read")
            .insert_header(("Authorization", create_jwt_authorization_header()))
            .to_request();

        // Send the test request
        let response = test::call_service(&mut app, req).await;

        // Assert the response
        assert_eq!(response.status(), StatusCode::OK);
        
        // Extract the response body
        let response_body = test::read_body(response).await;
        
        // Convert the response body to a string (if applicable)
        let response_body_str = String::from_utf8(response_body.to_vec()).unwrap();

        assert_eq!(response_body_str, "{\"key\":\"value\"}");
        let req1 = test::TestRequest::get()
            .uri("/read")
            .insert_header(("Authorization", "yy"))
            .to_request();

        // Send the test request
        let response = test::call_service(&mut app, req1).await;

        // Assert the response
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Add more assertions if needed
    }

    #[actix_rt::test]
    async fn test_all () {
        test_write_endpoint().await;
        test_read_endpoint().await
    }
}


//can you write and function to create valid JWT Authorization  header, read jwt serect from env:JWT_SECRET, read user first id from env:JWT_USERS, JWT_USERS is id list seprated by "," the JWT data need to be encoded is { id: USER_ID_FROM_ENV, exp: 999 }