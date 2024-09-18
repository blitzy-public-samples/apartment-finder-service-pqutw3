import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_user_registration():
    response = client.post("/api/users/register", json={
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "testpassword123"
    })
    assert response.status_code == 201
    assert "id" in response.json()
    assert response.json()["username"] == "testuser"
    assert response.json()["email"] == "testuser@example.com"

def test_user_login():
    response = client.post("/api/users/login", data={
        "username": "testuser",
        "password": "testpassword123"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "token_type" in response.json()

def test_listing_retrieval():
    response = client.get("/api/listings")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    
    # Test single listing retrieval
    if len(response.json()) > 0:
        listing_id = response.json()[0]["id"]
        response = client.get(f"/api/listings/{listing_id}")
        assert response.status_code == 200
        assert "id" in response.json()
        assert "title" in response.json()

def test_filter_creation():
    # Login first to get the token
    login_response = client.post("/api/users/login", data={
        "username": "testuser",
        "password": "testpassword123"
    })
    token = login_response.json()["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/filters", json={
        "name": "Test Filter",
        "criteria": {
            "min_price": 100000,
            "max_price": 500000,
            "bedrooms": 3,
            "bathrooms": 2
        }
    }, headers=headers)
    assert response.status_code == 201
    assert "id" in response.json()
    assert response.json()["name"] == "Test Filter"

def test_subscription_management():
    # Login first to get the token
    login_response = client.post("/api/users/login", data={
        "username": "testuser",
        "password": "testpassword123"
    })
    token = login_response.json()["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create a subscription
    response = client.post("/api/subscriptions", json={
        "filter_id": 1,  # Assuming filter with id 1 exists
        "notification_frequency": "daily"
    }, headers=headers)
    assert response.status_code == 201
    assert "id" in response.json()
    
    # Get subscriptions
    response = client.get("/api/subscriptions", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    
    # Update a subscription
    if len(response.json()) > 0:
        subscription_id = response.json()[0]["id"]
        response = client.put(f"/api/subscriptions/{subscription_id}", json={
            "notification_frequency": "weekly"
        }, headers=headers)
        assert response.status_code == 200
        assert response.json()["notification_frequency"] == "weekly"
    
    # Delete a subscription
    if len(response.json()) > 0:
        subscription_id = response.json()[0]["id"]
        response = client.delete(f"/api/subscriptions/{subscription_id}", headers=headers)
        assert response.status_code == 204

# HUMAN ASSISTANCE NEEDED
# The following tests may need to be adjusted based on the actual implementation details:
# 1. Ensure that the endpoint URLs match the actual API routes
# 2. Verify that the JSON structures for requests and responses align with the API specifications
# 3. Add more specific assertions to check for expected data in responses
# 4. Implement proper test data setup and teardown to ensure test isolation
# 5. Add error case testing for each endpoint (e.g., invalid inputs, unauthorized access)