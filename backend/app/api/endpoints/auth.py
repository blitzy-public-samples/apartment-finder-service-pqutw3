from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.core.security import create_access_token, get_password_hash, verify_password
from backend.app.db.database import get_db
from backend.app.schema.user import UserCreate, UserLogin
from backend.app.db.models import User

router = APIRouter()

@router.post('/register')
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user with hashed password
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Generate access token
    access_token = create_access_token(data={"sub": new_user.email})
    
    # Return user info and token
    return {
        "user": {
            "id": new_user.id,
            "email": new_user.email
        },
        "access_token": access_token,
        "token_type": "bearer"
    }

@router.post('/login')
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    # Verify user credentials
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    # Generate access token
    access_token = create_access_token(data={"sub": db_user.email})
    
    # Return token
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }