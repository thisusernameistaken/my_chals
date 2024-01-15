FROM ubuntu@sha256:c95a8e48bf88e9849f3e0f723d9f49fa12c5a00cfc6e60d2bc99d87555295e4c as app
ENV DEBIAN_FRONTEND=noninteractive 
RUN apt update && apt install -y libglib2.0-dev libcapstone-dev
COPY . /app

FROM pwn.red/jail
COPY --from=app / /srv
