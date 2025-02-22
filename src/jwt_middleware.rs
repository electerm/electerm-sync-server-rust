use actix_web::{
    dev::ServiceRequest,
    Error,
    HttpMessage,
    error::ErrorUnauthorized
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Serialize, Deserialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    id: String,
}

pub async fn jwt_middleware(req: ServiceRequest, credentials: BearerAuth) 
    -> Result<ServiceRequest, (Error, ServiceRequest)> {
    
    match check_jwt(credentials.token()) {
        Ok(user_id) => {
            req.extensions_mut().insert(user_id);
            Ok(req)
        },
        Err(_) => Err((ErrorUnauthorized("invalid token"), req))
    }
}

fn check_jwt(token: &str) -> Result<String, Error> {
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET not set");
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let mut validation = Validation::default();
    validation.algorithms = vec![Algorithm::HS256];
    validation.validate_exp = false;

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|_| ErrorUnauthorized("invalid token"))?;

    let user_ids_str = env::var("JWT_USERS").expect("JWT_USERS not set");
    let user_ids: Vec<&str> = user_ids_str.split(',').collect();
    let id = token_data.claims.id;

    if user_ids.contains(&id.as_str()) {
        Ok(id)
    } else {
        Err(ErrorUnauthorized("invalid user"))
    }
}