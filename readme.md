# ssh-over-tls
 
## Table of Contents



- [Introduction](#introduction)

- [Usage](#usage)

- [Configuration](#configuration)

- [Diagram](#diagram)

Introduction



This is a Go application that listens on a specified port for incoming connections and forwards them to either SSH or HTTP servers, depending on the protocol used. TLS certificates are used to secure the connections.





Usage



The following environment variables are required:



- SSH_SERVER_ADDR: The address of the SSH server to forward SSH connections to

- HTTP_SERVER_ADDR: The address of the HTTP server to forward HTTP connections to

- LISTEN_PORT: The port to listen on for incoming connections





Configuration


The following optional configuration settings can be specified via environment variables:

- SSL_CERT_PATH: The path to the SSL certificate file (default: cert.pem)

- SSL_KEY_PATH: The path to the SSL key file (default: key.pem)

Diagram

```
@startuml

title TLS Tunnel Diagram

actor User as U
participant "TLS Tunnel Application" as A
participant "SSH Server" as S
participant "HTTP Server" as H
participant "TLS Listener" as L

database Certificates

U -> A : Request Connection
A -> L : Listen on Port
L -> A : Incoming Connection
A -> L : Handle Connection
L -> S : Forward SSH Connection
L -> H : Forward HTTP Connection

alt SSH Connection
    S -> L : Handle SSH Connection
    L -> S : Forward SSH Connection
else HTTP Connection
    H -> L : Handle HTTP Connection
    L -> H : Forward HTTP Connection
end

L -> A : Close Connection
A -> U : Send Response

@enduml
```