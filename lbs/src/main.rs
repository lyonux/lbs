use tokio;

#[tokio::main]
async fn main() {
    tokio::spawn(async {
        println!("Hello, world!");
    })
    .await
    .unwrap();
}
