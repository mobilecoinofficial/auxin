FROM ghcr.io/rust-lang/rust:nightly as builder
WORKDIR /app
RUN rustup default nightly
# from https://stackoverflow.com/questions/58473606/cache-rust-dependencies-with-docker-build
COPY ./Cargo.toml .
COPY ./Cargo.lock .
COPY ./auxin/Cargo.toml /app/auxin/
COPY ./auxin_cli/Cargo.toml /app/auxin_cli/
RUN mkdir -p /app/auxin_cli/src /app/auxin/src
COPY auxin_protos /app/auxin_protos
COPY ./auxin_protos/build.rs.always /app/auxin_protos/build.rs
WORKDIR /app/auxin_cli
# build dummy auxin_cli using latest Cargo.toml/Cargo.lock
RUN echo 'fn main() { println!("Dummy!"); }' > ./src/lib.rs
RUN echo 'fn lib() { println!("Dummy!"); }' > ../auxin/src/lib.rs
RUN find /app/
RUN cargo build --release
# replace with latest source
RUN rm -r /app/auxin/src /app/auxin_cli/src
COPY ./auxin/src /app/auxin/src
COPY ./auxin/data /app/auxin/data
COPY ./auxin_cli/src /app/auxin_cli/src

RUN find /app/auxin_cli
RUN touch -a -m /app/auxin_cli/src/main.rs

RUN cargo +nightly build --release
FROM ubuntu:hirsute
RUN apt-get update && apt-get install -y jq curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/auxin-cli /app/auxin_cli
COPY ./echobot/init.sh /app
CMD ["/app/init.sh"]
