# Twirp Wire Protocol

This document defines the Twirp wire protocol over HTTP. The
current protocol version is v7.

## Overview

The Twirp wire protocol is a simple RPC protocol based on HTTP and
Protocol Buffers (proto). The protocol uses HTTP URLs to specify the
RPC endpoints, and sends/receives proto messages as HTTP
request/response bodies.

To use Twirp, developers first define their APIs using proto files,
then use Twirp tools to generate the client and the server libraries.
The generated libraries implement the Twirp wire protocol, using the
standard HTTP library provided by the programming language runtime or
the operating system. Once the client and the server are implemented,
the client can communicate with the server by making RPC calls.

The Twirp wire protocol supports both binary and JSON encodings of
proto messages, and works with any HTTP client and any HTTP version.

### URLs

In [ABNF syntax](https://tools.ietf.org/html/rfc5234), Twirp's URLs
have the following format:

```abnf
URL ::= Base-URL [ Prefix ] "/" [ Package "." ] Service "/" Method
```

The Twirp wire protocol uses HTTP URLs to specify the RPC
endpoints on the server for sending the requests. Such direct mapping
makes the request routing simple and efficient. The Twirp URLs have
the following components.

* **Base-URL** is the virtual location of a Twirp API server, which is
  typically published via API documentation or service discovery.
  Currently, it should only contain URL `scheme` and `authority`. For
  example, "https://example.com".
* **Prefix** is usually "/twirp", but it could be empty "", or an
  arbitrary path like "/my/custom/prefix".
* **Package** is the proto `package` name for an API, which is often
  considered as an API version. For example,
  `example.calendar.v1`. This component is omitted if the API
  definition doesn't have a package name.
* **Service** is the proto `service` name for an API. For example,
  `CalendarService`.
* **Method** is the proto `rpc` name for an API method. For example,
  `CreateEvent`.

### Requests

Twirp always uses HTTP POST method to send requests, because it
closely matches the semantics of RPC methods.

The **Request-Headers** are normal HTTP headers. The Twirp wire
protocol uses the following headers.

* **Content-Type** header indicates the proto message encoding, which
  should be one of "application/protobuf", "application/json". The
  server uses this value to decide how to parse the request body,
  and encode the response body.

The **Request-Body** is the encoded request message, contained in the
HTTP request body. The encoding is specified by the `Content-Type`
header.

### Responses

The **Response-Headers** are just normal HTTP response headers. The
Twirp wire protocol uses the following headers.

* **Content-Type** The value should be either "application/protobuf"
  or "application/json" to indicate the encoding of the response
  message. It must match the "Content-Type" header in the request.

The **Request-Body** is the encoded response message contained in the
HTTP response body. The encoding is specified by the `Content-Type`
header.

### Example

The following example shows a simple Echo API definition and its
corresponding wire payloads.

The example assumes the server base URL is "https://example.com".

```proto
syntax = "proto3";

package example.echoer;

service Echo {
  rpc Hello(HelloRequest) returns (HelloResponse);
}

message HelloRequest {
  string message;
}

message HelloResponse {
  string message;
}
```

**Proto Request**

```
POST /twirp/example.echoer.Echo/Hello HTTP/1.1
Host: example.com
Content-Type: application/protobuf
Content-Length: 15

<encoded HelloRequest>
```

**JSON Request**

```
POST /twirp/example.echoer.Echo/Hello HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 27

{"message":"Hello, World!"}
```

**Proto Response**

```
HTTP/1.1 200 OK
Content-Type: application/protobuf
Content-Length: 15

<encoded HelloResponse>
```

**JSON Response**

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 27

{"message":"Hello, World!"}
```


## Errors

Twirp error responses are always JSON-encoded, regardless of
the request's Content-Type, with a corresponding
`Content-Type: application/json` header. This ensures that
the errors are human-readable in any setting.

Twirp errors are a JSON object with the keys:

* **code**: One of the Twirp error codes as a string.
* **msg**: A human-readable message describing the error
  as a string.
* **meta**: (optional) An object with string values holding
  arbitrary additional metadata describing the error.

Example:

```json
{
  "code": "internal",
  "msg": "Something went wrong"
}
```

Example with metadata:

```json
{
  "code": "permission_denied",
  "msg": "Thou shall not pass",
  "meta": {
    "target": "Balrog",
    "power": "999"
  }
}
```

### Error Codes

Twirp errors always include an error code. This code is represented
as a string and must be one of a fixed set of codes, listed in the
table below. Each code has an associated HTTP Status Code. When a
server responds with the given error code, it must set the
corresponding HTTP Status Code for the response.

| Twirp Error Code    | HTTP Status | Description
| ------------------- | ----------- | -----------
| canceled            | 408 | The operation was cancelled.
| unknown             | 500 | An unknown error occurred. For example, this can be used when handling errors raised by APIs that do not return any error information.
| invalid_argument    | 400 | The client specified an invalid argument. This indicates arguments that are invalid regardless of the state of the system (i.e. a malformed file name, required argument, number out of range, etc.).
| malformed           | 400 | The client sent a message which could not be decoded. This may mean that the message was encoded improperly or that the client and server have incompatible message definitions.
| deadline_exceeded   | 408 | Operation expired before completion. For operations that change the state of the system, this error may be returned even if the operation has completed successfully (timeout).
| not_found           | 404 | Some requested entity was not found.
| bad_route           | 404 | The requested URL path wasn't routable to a Twirp service and method. This is returned by generated server code and should not be returned by application code (use "not_found" or "unimplemented" instead).
| already_exists      | 409 | An attempt to create an entity failed because one already exists.
| permission_denied   | 403 | The caller does not have permission to execute the specified operation. It must not be used if the caller cannot be identified (use "unauthenticated" instead).
| unauthenticated     | 401 | The request does not have valid authentication credentials for the operation.
| resource_exhausted  | 429 | Some resource has been exhausted or rate-limited, perhaps a per-user quota, or perhaps the entire file system is out of space.
| failed_precondition | 412 | The operation was rejected because the system is not in a state required for the operation's execution. For example, doing an rmdir operation on a directory that is non-empty, or on a non-directory object, or when having conflicting read-modify-write on the same resource.
| aborted             | 409 | The operation was aborted, typically due to a concurrency issue like sequencer check failures, transaction aborts, etc.
| out_of_range        | 400 | The operation was attempted past the valid range. For example, seeking or reading past end of a paginated collection. Unlike "invalid_argument", this error indicates a problem that may be fixed if the system state changes (i.e. adding more items to the collection). There is a fair bit of overlap between "failed_precondition" and "out_of_range". We recommend using "out_of_range" (the more specific error) when it applies so that callers who are iterating through a space can easily look for an "out_of_range" error to detect when they are done.
| unimplemented       | 501 | The operation is not implemented or not supported/enabled in this service.
| internal            | 500 | When some invariants expected by the underlying system have been broken. In other words, something bad happened in the library or backend service. Twirp specific issues like wire and serialization problems are also reported as "internal" errors.
| unavailable         | 503 | The service is currently unavailable. This is most likely a transient condition and may be corrected by retrying with a backoff.
| data_loss            | 500 | The operation resulted in unrecoverable data loss or corruption.

