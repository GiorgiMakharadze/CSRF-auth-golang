# CSRF Auth Golang

This project demonstrates a CSRF (Cross-Site Request Forgery) protected authentication system using Golang. It includes user registration, login, logout, delete user and protected routes with JWT (JSON Web Tokens) for authentication and CSRF tokens for additional security.

## Features

- User registration, deletion, logout and login with bcrypt password hashing
- JWT-based authentication
- CSRF protection
- Middleware for authentication and CSRF token validation
- In-memory database for storing users and refresh tokens
- Secure storage of private and public RSA keys for JWT signing and verification

## Setup and Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/GiorgiMakharadze/CSRF-auth-golang.git
   cd CSRF-auth-golang
   ```

2. **Generate RSA keys:**

Generate the RSA private key:

```sh
openssl genrsa -out keys/app.rsa 2048
```

Extract the public key:

```sh
openssl rsa -in keys/app.rsa -pubout -out keys/app.rsa.pub
```

3. **Install Dependencies:**

```sh
go mod tidy
```

4. **Run the Application:**

```sh
go run main.go
```

4. **Access the Application:**

Open your browser and navigate to `http://localhost:9000/register`.
