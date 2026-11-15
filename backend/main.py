from contextlib import asynccontextmanager
from typing import Literal
from fastapi import FastAPI, HTTPException 
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from graph import build_graph




@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.graph = build_graph()
    yield


app = FastAPI(title="Scam Detector API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)

class ScamRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8000, description="Message, email, offer or link text to check")


class ScamResponse(BaseModel):
    verdict: Literal["scam", "not scam"]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/classify", response_model=ScamResponse)
async def classify(req: ScamRequest):
    try:
        result = await app.state.graph.ainvoke({"text": req.text})
    except Exception as exc: 
        raise HTTPException(status_code=502, detail=f"Classification failed: {exc}")
    return {"verdict": result["verdict"]}