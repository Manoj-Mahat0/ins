from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import jwt
import bcrypt
import os

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URL = os.getenv("MONGO_URL", "mongodb+srv://manojmahato08779_db_user:0SiDNdWTYYMggFkp@cluster0.3nypxyg.mongodb.net/?appName=Cluster0")
client = AsyncIOMotorClient(MONGO_URL)
db = client.student_task_db

# JWT Config
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
security = HTTPBearer()

# Models
class Student(BaseModel):
    name: str
    email: EmailStr
    course: str

class Task(BaseModel):
    title: str
    description: str
    status: str = "pending"

class AssignTask(BaseModel):
    title: str
    description: str
    student_id: str
    status: str = "pending"

class User(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"  # "admin" or "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

# Helper functions
def create_token(user_id: str):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["user_id"]
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

async def verify_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload["user_id"]
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user or user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        return user_id
    except HTTPException:
        raise
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# Question 1: Student APIs
@app.post("/students", status_code=201)
async def add_student(student: Student):
    # Check if student email already exists
    existing_student = await db.students.find_one({"email": student.email})
    if existing_student:
        raise HTTPException(status_code=400, detail="Student with this email already exists")
    
    # Add student
    student_dict = student.dict()
    student_dict["created_at"] = datetime.utcnow()
    result = await db.students.insert_one(student_dict)
    
    # Auto-create user account with default password "123456"
    existing_user = await db.users.find_one({"email": student.email})
    if not existing_user:
        default_password = "123456"
        hashed_password = bcrypt.hashpw(default_password.encode(), bcrypt.gensalt())
        user_dict = {
            "username": student.name,
            "email": student.email,
            "password": hashed_password,
            "role": "user",
            "created_at": datetime.utcnow()
        }
        await db.users.insert_one(user_dict)
    
    return {
        "id": str(result.inserted_id), 
        "message": "Student added successfully. Login credentials created with default password: 123456"
    }

@app.get("/students")
async def get_all_students():
    students = []
    async for student in db.students.find():
        student["id"] = str(student.pop("_id"))
        students.append(student)
    return students

@app.delete("/students/{student_id}")
async def delete_student(student_id: str):
    result = await db.students.delete_one({"_id": ObjectId(student_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Student not found")
    return {"message": "Student deleted successfully"}

# Question 2: Task APIs
@app.post("/tasks", status_code=201)
async def add_task(task: Task):
    task_dict = task.dict()
    task_dict["created_at"] = datetime.utcnow()
    result = await db.tasks.insert_one(task_dict)
    return {"id": str(result.inserted_id), "message": "Task added successfully"}

@app.get("/tasks")
async def get_all_tasks():
    tasks = []
    async for task in db.tasks.find():
        task["id"] = str(task.pop("_id"))
        tasks.append(task)
    return tasks

@app.put("/tasks/{task_id}")
async def update_task_status(task_id: str, status: str):
    result = await db.tasks.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {"status": status}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task updated successfully"}

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    result = await db.tasks.delete_one({"_id": ObjectId(task_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deleted successfully"}

# Question 3: Authentication + Protected APIs
@app.post("/register", status_code=201)
async def register_user(user: User):
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    user_dict = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "role": user.role,
        "created_at": datetime.utcnow()
    }
    result = await db.users.insert_one(user_dict)
    return {"message": "User registered successfully"}

@app.post("/login")
async def login_user(user: UserLogin):
    db_user = await db.users.find_one({"email": user.email})
    if not db_user or not bcrypt.checkpw(user.password.encode(), db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(str(db_user["_id"]))
    return {
        "token": token, 
        "username": db_user["username"],
        "role": db_user.get("role", "user")
    }

# Protected Task APIs
@app.post("/protected/tasks", status_code=201)
async def add_protected_task(task: Task, user_id: str = Depends(verify_token)):
    task_dict = task.dict()
    task_dict["user_id"] = user_id
    task_dict["created_at"] = datetime.utcnow()
    result = await db.protected_tasks.insert_one(task_dict)
    return {"id": str(result.inserted_id), "message": "Task added successfully"}

@app.get("/protected/tasks")
async def get_protected_tasks(user_id: str = Depends(verify_token)):
    tasks = []
    async for task in db.protected_tasks.find({"user_id": user_id}):
        task["id"] = str(task.pop("_id"))
        tasks.append(task)
    return tasks

@app.put("/protected/tasks/{task_id}")
async def update_protected_task(task_id: str, status: str, user_id: str = Depends(verify_token)):
    result = await db.protected_tasks.update_one(
        {"_id": ObjectId(task_id), "user_id": user_id},
        {"$set": {"status": status}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task updated successfully"}

@app.delete("/protected/tasks/{task_id}")
async def delete_protected_task(task_id: str, user_id: str = Depends(verify_token)):
    result = await db.protected_tasks.delete_one({"_id": ObjectId(task_id), "user_id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deleted successfully"}

# Admin APIs - Assign tasks to students
@app.post("/admin/assign-task", status_code=201)
async def assign_task_to_student(task: AssignTask, admin_id: str = Depends(verify_admin)):
    # Check if student exists
    student = await db.students.find_one({"_id": ObjectId(task.student_id)})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    task_dict = {
        "title": task.title,
        "description": task.description,
        "status": task.status,
        "student_id": task.student_id,
        "student_name": student["name"],
        "student_email": student["email"],
        "assigned_by": admin_id,
        "created_at": datetime.utcnow()
    }
    result = await db.assigned_tasks.insert_one(task_dict)
    return {"id": str(result.inserted_id), "message": "Task assigned successfully"}

@app.get("/admin/assigned-tasks")
async def get_all_assigned_tasks(admin_id: str = Depends(verify_admin)):
    tasks = []
    async for task in db.assigned_tasks.find():
        task["id"] = str(task.pop("_id"))
        tasks.append(task)
    return tasks

@app.put("/admin/assigned-tasks/{task_id}")
async def update_assigned_task(task_id: str, status: str, admin_id: str = Depends(verify_admin)):
    result = await db.assigned_tasks.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {"status": status}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task updated successfully"}

@app.delete("/admin/assigned-tasks/{task_id}")
async def delete_assigned_task(task_id: str, admin_id: str = Depends(verify_admin)):
    result = await db.assigned_tasks.delete_one({"_id": ObjectId(task_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deleted successfully"}

# Student APIs - View assigned tasks
@app.get("/student/my-tasks")
async def get_my_assigned_tasks(user_id: str = Depends(verify_token)):
    # Get user's email to match with student
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Find student by email
    student = await db.students.find_one({"email": user["email"]})
    if not student:
        return []
    
    tasks = []
    async for task in db.assigned_tasks.find({"student_id": str(student["_id"])}):
        task["id"] = str(task.pop("_id"))
        tasks.append(task)
    return tasks

@app.put("/student/my-tasks/{task_id}")
async def update_my_task_status(task_id: str, status: str, user_id: str = Depends(verify_token)):
    # Get user's email
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Find student
    student = await db.students.find_one({"email": user["email"]})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    result = await db.assigned_tasks.update_one(
        {"_id": ObjectId(task_id), "student_id": str(student["_id"])},
        {"$set": {"status": status}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task updated successfully"}

@app.put("/change-password")
async def change_password(request: ChangePasswordRequest, user_id: str = Depends(verify_token)):
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify current password
    if not bcrypt.checkpw(request.current_password.encode(), user["password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Update to new password
    hashed_password = bcrypt.hashpw(request.new_password.encode(), bcrypt.gensalt())
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password": hashed_password}}
    )
    return {"message": "Password changed successfully"}

@app.get("/")
async def root():
    return {"message": "Student Task Manager API"}
