FROM rust:latest as libbuilder
WORKDIR /app/auxin
RUN rustup update nightly && rustup default nightly
# the idea here is to cache deps
# # copy in our deps
# COPY Cargo* ./
# COPY auxin/Cargo* ./auxin/
# COPY auxin_protos/Cargo* ./auxin_protos/
# COPY auxin_cli/Cargo* ./auxin_cli/
# COPY rust-toolchain ./
# # write something so it can compile deps. bash is needed for globs
# RUN bash -c "mkdir -p auxin{,_protos,_cli}/src  \
#     && echo 'fn main() { println!(\"h\"); }' | tee auxin{,_protos,_cli}/src/main.rs"
# RUN cargo build --release 
# # release with our actual code
# RUN bash -c "rm auxin{,_protos,_cli}/src/main.rs target/release/deps/auxin*"
ENV foo=bar
COPY ./* ./
RUN cargo build --release 

FROM ubuntu:latest
WORKDIR /app
COPY --from=libbuilder /app/auxin/target/release /app/auxin
COPY state healthcheck.sh  ./
ENTRYPOINT ["/app/healthcheck.sh"] 
