import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.models import Base, get_db, User, Task
from app.auth import get_password_hash


# Create a test database
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """Create a fresh database for each test."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """Create a test client with database override."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def test_user(db_session):
    """Create a test user."""
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password=get_password_hash("testpassword")
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def auth_token(client, test_user):
    """Get authentication token for test user."""
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpassword"}
    )
    return response.json()["access_token"]


# ========== POSITIVE TESTS ==========

def test_register_user_success(client):
    """Test successful user registration."""
    response = client.post(
        "/register",
        json={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "securepassword"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "newuser@example.com"
    assert "id" in data
    assert "hashed_password" not in data


def test_login_success(client, test_user):
    """Test successful login with JWT token."""
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 0


def test_create_task_success(client, auth_token):
    """Test successfully creating a task."""
    response = client.post(
        "/tasks",
        json={
            "title": "Test Task",
            "description": "This is a test task",
            "status": "pending"
        },
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Test Task"
    assert data["description"] == "This is a test task"
    assert data["status"] == "pending"
    assert "id" in data


def test_get_tasks_success(client, auth_token, test_user, db_session):
    """Test successfully retrieving all tasks."""
    # Create some tasks
    task1 = Task(title="Task 1", description="First task", owner_id=test_user.id)
    task2 = Task(title="Task 2", description="Second task", owner_id=test_user.id)
    db_session.add(task1)
    db_session.add(task2)
    db_session.commit()
    
    response = client.get(
        "/tasks",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["title"] in ["Task 1", "Task 2"]


def test_get_task_by_id_success(client, auth_token, test_user, db_session):
    """Test successfully retrieving a task by ID."""
    task = Task(title="Specific Task", description="A specific task", owner_id=test_user.id)
    db_session.add(task)
    db_session.commit()
    db_session.refresh(task)
    
    response = client.get(
        f"/tasks/{task.id}",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Specific Task"
    assert data["id"] == task.id


def test_update_task_success(client, auth_token, test_user, db_session):
    """Test successfully updating a task."""
    task = Task(title="Original Task", description="Original", owner_id=test_user.id)
    db_session.add(task)
    db_session.commit()
    db_session.refresh(task)
    
    response = client.put(
        f"/tasks/{task.id}",
        json={"title": "Updated Task", "status": "completed"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Updated Task"
    assert data["status"] == "completed"


def test_delete_task_success(client, auth_token, test_user, db_session):
    """Test successfully deleting a task."""
    task = Task(title="Task to Delete", owner_id=test_user.id)
    db_session.add(task)
    db_session.commit()
    db_session.refresh(task)
    
    response = client.delete(
        f"/tasks/{task.id}",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 204
    
    # Verify task is deleted
    deleted_task = db_session.query(Task).filter(Task.id == task.id).first()
    assert deleted_task is None


def test_get_current_user_success(client, auth_token):
    """Test successfully getting current user information."""
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert "id" in data


# ========== NEGATIVE TESTS ==========

def test_access_tasks_without_token(client):
    """Test accessing tasks without authentication token (expecting 401)."""
    response = client.get("/tasks")
    assert response.status_code == 401
    assert "detail" in response.json()


def test_create_task_without_token(client):
    """Test creating a task without authentication token (expecting 401)."""
    response = client.post(
        "/tasks",
        json={"title": "Unauthorized Task", "description": "Should fail"}
    )
    assert response.status_code == 401


def test_access_task_by_id_without_token(client):
    """Test accessing a specific task without token (expecting 401)."""
    response = client.get("/tasks/1")
    assert response.status_code == 401


def test_login_with_wrong_password(client, test_user):
    """Test login with incorrect password."""
    response = client.post(
        "/token",
        data={"username": "testuser", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert "detail" in response.json()


def test_login_with_nonexistent_user(client):
    """Test login with non-existent username."""
    response = client.post(
        "/token",
        data={"username": "nonexistent", "password": "password"}
    )
    assert response.status_code == 401


def test_get_nonexistent_task(client, auth_token):
    """Test getting a task that doesn't exist."""
    response = client.get(
        "/tasks/99999",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_update_nonexistent_task(client, auth_token):
    """Test updating a task that doesn't exist."""
    response = client.put(
        "/tasks/99999",
        json={"title": "Updated"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 404


def test_delete_nonexistent_task(client, auth_token):
    """Test deleting a task that doesn't exist."""
    response = client.delete(
        "/tasks/99999",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 404


def test_register_duplicate_username(client, test_user):
    """Test registering with an already existing username."""
    response = client.post(
        "/register",
        json={
            "username": "testuser",
            "email": "different@example.com",
            "password": "password"
        }
    )
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"].lower()


def test_register_duplicate_email(client, test_user):
    """Test registering with an already existing email."""
    response = client.post(
        "/register",
        json={
            "username": "differentuser",
            "email": "test@example.com",
            "password": "password"
        }
    )
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"].lower()


# ========== EDGE CASE TESTS ==========

def test_create_task_with_empty_title(client, auth_token):
    """Test creating a task with empty title (edge case)."""
    response = client.post(
        "/tasks",
        json={"title": "", "description": "Empty title task"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 422  # Validation error


def test_create_task_with_missing_title(client, auth_token):
    """Test creating a task without title field."""
    response = client.post(
        "/tasks",
        json={"description": "No title"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 422  # Validation error


def test_update_task_with_empty_title(client, auth_token, test_user, db_session):
    """Test updating a task with empty title (edge case)."""
    task = Task(title="Valid Task", owner_id=test_user.id)
    db_session.add(task)
    db_session.commit()
    db_session.refresh(task)
    
    response = client.put(
        f"/tasks/{task.id}",
        json={"title": ""},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 400
    assert "cannot be empty" in response.json()["detail"].lower()


def test_create_task_with_long_title(client, auth_token):
    """Test creating a task with very long title."""
    long_title = "A" * 1000
    response = client.post(
        "/tasks",
        json={"title": long_title, "description": "Long title task"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    # Should succeed but test the edge case
    assert response.status_code in [201, 422]  # Depends on validation rules


def test_create_task_with_special_characters(client, auth_token):
    """Test creating a task with special characters in title."""
    response = client.post(
        "/tasks",
        json={"title": "Task !@#$%^&*()", "description": "Special chars"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Task !@#$%^&*()"


def test_create_task_with_null_description(client, auth_token):
    """Test creating a task with null description."""
    response = client.post(
        "/tasks",
        json={"title": "Task without description", "description": None},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Task without description"
    assert data["description"] is None


def test_access_other_user_task(client, auth_token, db_session):
    """Test accessing another user's task (should fail)."""
    # Create another user
    other_user = User(
        username="otheruser",
        email="other@example.com",
        hashed_password=get_password_hash("password")
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)
    
    # Create task for other user
    task = Task(title="Other User Task", owner_id=other_user.id)
    db_session.add(task)
    db_session.commit()
    db_session.refresh(task)
    
    # Try to access it with first user's token
    response = client.get(
        f"/tasks/{task.id}",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 404  # Should not find it (filtered by owner)


def test_invalid_jwt_token(client):
    """Test accessing endpoint with invalid JWT token."""
    response = client.get(
        "/tasks",
        headers={"Authorization": "Bearer invalid_token_here"}
    )
    assert response.status_code == 401


def test_malformed_authorization_header(client):
    """Test accessing endpoint with malformed authorization header."""
    response = client.get(
        "/tasks",
        headers={"Authorization": "InvalidFormat token"}
    )
    assert response.status_code == 401

