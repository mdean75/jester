FROM rust:1.72

WORKDIR app

COPY . .

RUN cargo build --release

ENTRYPOINT /app/target/release/jester
