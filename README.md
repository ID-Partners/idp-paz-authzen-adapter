# Authorization Proxy Service

## Overview
This project is an authorization proxy service that integrates with Ping Authorize and provides a set of APIs for evaluating access control policies, searching for subjects and resources, and making authorization decisions. The service is built in Go and acts as an intermediary between clients and a Policy Decision Point (PDP).

This implementation conforms to the [AuthZen Interop Specification](https://authzen-interop.net/docs/intro/), ensuring interoperability with authorization frameworks and standardized access control mechanisms.

## Features
- **Authorization Evaluation API**: Evaluates access requests based on subject, action, resource, and context.
- **Subject Search API**: Retrieves subjects matching a given action-resource pair.
- **Resource Search API**: Retrieves resources matching a given subject-action pair.
- **Ping Authorize Integration**: Queries Ping Authorize for policy decisions.
- **Environment Configuration**: Uses environment variables for configuration.
- **Secure API Key Authentication**: Validates API requests with Bearer token authentication.
- **Batch Evaluation Support**: Handles batch evaluation requests for multiple access queries.

## API Endpoints
### Authorization Evaluation
**Endpoint:** `/access/v1/evaluation`  
**Method:** `POST`  
**Description:** Evaluates a subject's authorization to perform an action on a resource.

### Batch Authorization Evaluation
**Endpoint:** `/access/v1/evaluations`  
**Method:** `POST`  
**Description:** Processes multiple evaluation requests in a single batch.

### Subject Search
**Endpoint:** `/access/v1/search/subject`  
**Method:** `POST`  
**Description:** Searches for subjects that match the given action and resource.

### Resource Search
**Endpoint:** `/access/v1/search/resource`  
**Method:** `POST`  
**Description:** Searches for resources that match the given subject and action.

### Health Check
**Endpoint:** `/health`  
**Method:** `GET`  
**Description:** Returns `200 OK` to indicate service health.

## Environment Variables
| Variable               | Description                                      |
|------------------------|--------------------------------------------------|
| `PORT`                 | Port on which the service listens (default: 8080) |
| `API_KEY`              | API key required for authentication            |
| `QUERY_URL`            | URL of the PDP query endpoint                  |
| `PDP_URL`              | URL of the authorization decision endpoint      |
| `PDP_SECRET_HEADER`    | HTTP header name for PDP authentication token  |
| `PDP_SECRET`           | Secret token for PDP authentication            |
| `PDP_DOMAIN_PREFIX`    | Domain prefix used in PDP requests             |
| `PDP_ATTRIBUTE_PREFIX` | Attribute prefix for query parameters          |
| `PDP_SERVICE`          | PDP service identifier                         |
| `PDP_ACTION`           | PDP action identifier                          |

## Running the Service
### Prerequisites
- Go 1.18+
- Ping Authorize setup with governance policies
- Compliance with [AuthZen Interop Specification](https://authzen-interop.net/docs/intro/)

### Installation
1. Clone the repository:
   ```sh
   git clone <repository-url>
   cd <repository-folder>
   ```
2. Install dependencies:
   ```sh
   go mod tidy
   ```

### Running the Service
1. Set environment variables in a `.env` file or export them in your shell.
2. Start the service:
   ```sh
   go run main.go
   ```
3. The service will be available on `http://localhost:8080` by default.

### Docker Support
To run the service in a Docker container:
```sh
docker build -t auth-proxy .
docker run -p 8080:8080 --env-file .env auth-proxy
```

## Authentication
All API endpoints require a Bearer token in the `Authorization` header:
```sh
curl -X POST "http://localhost:8080/access/v1/evaluation" \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{ "subject": {"type": "user", "identity": "12345"}, "action": {"name": "read"}, "resource": {"type": "document", "id": "abc-123"} }'
```

## Logging and Debugging
- Logs include request details, environment variables, and decision responses.
- Debugging can be enabled by setting the appropriate log levels in the Go application.

## Contributing
- Fork the repository
- Create a feature branch
- Submit a pull request with changes

## License
This project is licensed under the MIT License.

---
For more details, contact the repository maintainer.

