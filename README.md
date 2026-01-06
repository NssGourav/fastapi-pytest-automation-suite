# QA Task Manager API

A professional FastAPI application with OAuth2/JWT authentication, CRUD operations for task management, and comprehensive Pytest automation test suite. Built to demonstrate expertise in Python, FastAPI, Pytest, and CI/CD practices.

## Features

- **FastAPI Backend** with SQLite database
- **OAuth2/JWT Authentication** using python-jose
- **CRUD Endpoints** for Task management (Title, Description, Status)
- **Comprehensive Test Suite** with Pytest:
  - Positive test cases
  - Negative test cases (401 Unauthorized, 404 Not Found, etc.)
  - Edge case testing (empty fields, invalid data, etc.)
- **CI/CD Pipeline** with GitHub Actions
- **Modular Architecture** with separation of concerns

## Project Structure

```
fastapi-pytest-automation-suite/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI application and endpoints
│   ├── auth.py          # OAuth2/JWT authentication logic
│   ├── models.py        # SQLAlchemy models and database setup
│   └── config.py        # Environment configuration
├── tests/
│   ├── __init__.py
│   └── test_api.py      # Comprehensive Pytest test suite
├── .github/
│   └── workflows/
│       └── python-tests.yml  # GitHub Actions CI/CD workflow
├── requirements.txt     # Python dependencies
├── env.example          # Environment variables template
└── README.md
```

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd fastapi-pytest-automation-suite
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Set up environment variables:**
   ```bash
   cp env.example .env
   ```
   Then edit `.env` and update the `SECRET_KEY` with a strong random key.

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

1. **Start the FastAPI server:**
   ```bash
   uvicorn app.main:app --reload
   ```

2. **Access the API:**
   - API Documentation: http://localhost:8000/docs
   - Alternative docs: http://localhost:8000/redoc

## API Endpoints

### Authentication
- `POST /register` - Register a new user
- `POST /token` - Login and get JWT access token
- `GET /users/me` - Get current user information

### Tasks (Requires Authentication)
- `POST /tasks` - Create a new task
- `GET /tasks` - Get all tasks for the current user
- `GET /tasks/{task_id}` - Get a specific task
- `PUT /tasks/{task_id}` - Update a task
- `DELETE /tasks/{task_id}` - Delete a task

## Testing

### Run All Tests
```bash
pytest tests/ -v
```

### Run with Coverage
```bash
pytest tests/ --cov=app --cov-report=html
```

### Test Categories

The test suite includes:

1. **Positive Tests:**
   - User registration
   - Login with JWT token
   - Creating, reading, updating, and deleting tasks
   - Getting current user information

2. **Negative Tests:**
   - Accessing endpoints without authentication (401 Unauthorized)
   - Invalid login credentials
   - Accessing non-existent resources (404 Not Found)
   - Duplicate username/email registration

3. **Edge Case Tests:**
   - Empty title validation
   - Missing required fields
   - Special characters in input
   - Accessing other users' tasks
   - Invalid JWT tokens

## CI/CD

The project includes a GitHub Actions workflow (`.github/workflows/python-tests.yml`) that:
- Triggers on push and pull requests
- Tests against Python 3.10 and 3.11
- Installs dependencies from `requirements.txt`
- Runs the Pytest test suite
- Generates and uploads test reports

## Example Usage

### 1. Register a User
```bash
curl -X POST "http://localhost:8000/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "securepassword"
  }'
```

### 2. Login and Get Token
```bash
curl -X POST "http://localhost:8000/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john_doe&password=securepassword"
```

### 3. Create a Task
```bash
curl -X POST "http://localhost:8000/tasks" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Complete QA Testing",
    "description": "Finish the automation test suite",
    "status": "in_progress"
  }'
```

### 4. Get All Tasks
```bash
curl -X GET "http://localhost:8000/tasks" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Technologies Used

- **FastAPI** - Modern, fast web framework for building APIs
- **SQLAlchemy** - SQL toolkit and ORM
- **Pytest** - Testing framework
- **python-jose** - JWT token handling
- **passlib** - Password hashing
- **httpx** - HTTP client for testing
- **GitHub Actions** - CI/CD pipeline

## Notes

- The database file (`qa_task_manager.db`) is created automatically on first run
- JWT tokens expire after 30 minutes (configurable in `.env` file)
- All task operations are scoped to the authenticated user
- The test suite uses an in-memory SQLite database for isolation
- **Important**: Create a `.env` file from `env.example` and set a strong `SECRET_KEY` for production use

## License

This project is created for demonstration purposes for the PipesHub QA Intern role application.