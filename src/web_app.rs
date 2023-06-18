use actix_web::{HttpResponse, Responder};


pub async fn test() -> impl Responder {
    HttpResponse::Ok().body("ok")
}
