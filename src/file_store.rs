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
    // exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    id: String,
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
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET not set");
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let mut validation = Validation::default();
    validation.algorithms = vec![Algorithm::HS256];
    validation.validate_exp = false;
    let token_data = decode::<Claims>(&token, &decoding_key, &validation);
    match token_data {
        Ok(token_data) => {
            let user_ids_str = env::var("JWT_USERS").expect("USER_IDS not set");
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
    let mut file_path = env::var("FILE_STORE_PATH").expect("FILE_STORE_PATH not set");
    file_path.push_str("/");
    file_path.push_str(&user_id);
    file_path.push_str(".json");
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
    let mut file_path = env::var("FILE_STORE_PATH").expect("FILE_STORE_PATH not set");
    file_path.push_str("/");
    file_path.push_str(&user_id);
    file_path.push_str(".json");
    let mut file = File::open(file_path).expect("Unable to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Unable to read file");

    let json_data: Value = serde_json::from_str(&contents).expect("Unable to parse JSON");

    HttpResponse::Ok().json(json_data)
}