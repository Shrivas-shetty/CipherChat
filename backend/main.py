from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth import router as auth_router
from database.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs when the server starts
    init_db()

    yield

    # Runs when the server shuts down
    # Put cleanup code here later if needed


app = FastAPI(lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "CipherChat Backend is running!"
    }


app.include_router(auth_router)