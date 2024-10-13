mod utility;

use sha2::{Sha256, Digest}; // Importing SHA-256 functions
use actix_web::{web, Error, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use actix_files as fs;
use utility::{login_responsee_generator, verifier_generator};


#[derive(Deserialize, Serialize)]
struct LoginRequest {
    username: String,
    client_pk: String,
}

#[derive(Serialize)]
struct LoginResponse {
    salt: String,
    server_pk: String,
}

#[derive(Deserialize)]
struct SubmitPasswordRequest {
    proof: String,
}

#[derive(Serialize)]
struct Secret {
    status: String,
    message: String
}

struct AppState {
    client_pk: Mutex<Option<String>>,
    server_pk: Mutex<Option<String>>,
    session_key: Mutex<Option<String>>,
}

async fn index() -> impl Responder {
    fs::NamedFile::open("index.html").unwrap()
}

// Define the restricted resources to send on successful validation
fn restricted_resources() -> &'static str {
    "Restricted resources: [Top Secret Data Here]"
}

async fn submit(form: web::Json<LoginRequest>, data: web::Data<Arc<AppState>>) -> impl Responder {
    println!("Received form data: username: {}, client_pk: {}", form.username, form.client_pk);

//For logging user retrive salt 's' and verrifier 'v' from DB
let s = "nothingupmysleeve";
let v = verifier_generator(s.to_string(), "ghosh".to_string());

    let (server_pk, session_key) = login_responsee_generator(&form.client_pk, &v);

// Store the server_pk and session_key in the shared state
{
    let mut client_pk_guard = data.client_pk.lock().unwrap();
    let mut server_pk_guard = data.server_pk.lock().unwrap();
    let mut session_key_guard = data.session_key.lock().unwrap();
    *client_pk_guard = Some(form.client_pk.clone());
    *server_pk_guard = Some(server_pk.to_string().clone());
    *session_key_guard = Some(session_key);
}

    let response = LoginResponse {
        salt: s.to_string(),
        server_pk: server_pk.to_string(),
    };
    
    HttpResponse::Ok().json(response)
}

// Function to handle the password submission, where we parse JSON, compare, and respond accordingly
async fn submitfinal(
    form: web::Json<SubmitPasswordRequest>, 
    data: web::Data<Arc<AppState>>
) -> Result<impl Responder, Error> {
    let input_proof = &form.proof; // Extract M1 from the JSON

    // Fetch the stored server_pk and session_key from the shared state
    let (client_pk, server_pk, session_key) = {
        let server_pk_guard = data.server_pk.lock().unwrap();
        let client_pk_guard = data.client_pk.lock().unwrap();
        let session_key_guard = data.session_key.lock().unwrap();
        match (&*client_pk_guard, &*server_pk_guard, &*session_key_guard) {
            (Some(client_pk),Some(server_pk), Some(session_key)) => (client_pk.clone(),server_pk.clone(), session_key.clone()),
            _ => return Ok(HttpResponse::Unauthorized().body("Access denied: Missing session data")),
        }
    };


    let concatenated = format!("{}{}{}", client_pk, server_pk,  session_key);
    let mut hasher = Sha256::new();
    hasher.update(concatenated);
    let hash = hasher.finalize();

    // The predefined string to compare against
    let expected_proof = hex::encode(hash);

    // Compare the extracted string to the expected string
    if *input_proof == expected_proof {
        let response = Secret {
            status: "ok".to_string(),
            message: "attack in dawn".to_string()
        };
        // If it matches, return restricted resources
        Ok(HttpResponse::Ok().json(response))
    } else {
        // If it doesn't match, return an error
        Ok(HttpResponse::Unauthorized().body("Access denied: Invalid proof"))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let shared_data = Arc::new(AppState {
        client_pk: Mutex::new(None),
        server_pk: Mutex::new(None),
        session_key: Mutex::new(None),
    });

    actix_web::HttpServer::new(move|| {
        actix_web::App::new()
            .app_data(web::Data::new(shared_data.clone()))
            .service(fs::Files::new("/static", "static").show_files_listing())
            .route("/", web::get().to(index))
            .route("/submitUsername", web::post().to(submit))
            .route("/submitPassword", web::post().to(submitfinal))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}