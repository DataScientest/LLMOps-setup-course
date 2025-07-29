from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import requests
import os
import mlflow
import openai
from litellm import completion_cost
from mlflow.entities.span import SpanType
from mlflow.entities.span_event import SpanEvent

from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

# Get LiteLLM's URL from environment variables, with a default for local dev
LITELLM_URL = os.getenv("LITELLM_URL", "http://litellm:8000")

# Initialize MLflow tracking
mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000"))

# Configure OpenAI client to point to LiteLLM proxy
client = openai.OpenAI(
    api_key="sk-1234",  # LiteLLM proxy requires any API key
    base_url=LITELLM_URL
)

def get_default_model():
    """Get the best available model based on priority."""
    print(f"DEBUG: Getting default model from {LITELLM_URL}")
    try:
        response = requests.get(f"{LITELLM_URL}/models")
        response.raise_for_status()
        available_models = [model["id"] for model in response.json().get("data", [])]
        
        print(f"DEBUG: Available models: {available_models}")
        
        # Priority order: Groq Kimi first, then fallbacks
        priority_models = [
            "groq-kimi-primary",  # Our Groq Kimi model via LiteLLM
            "gpt-4o-secondary", 
            "gemini-third", 
            "openrouter-fallback"
        ]
        
        for model in priority_models:
            if model in available_models:
                print(f"DEBUG: Selected model: {model}")
                return model
                
    except Exception as e:
        print(f"DEBUG: Error getting models: {e}")
    
    print("DEBUG: Using fallback: groq-kimi-primary")
    return "groq-kimi-primary"

# --- Pydantic Models for API requests and responses ---
class PromptRequest(BaseModel):
    prompt: str
    # The default model is our LiteLLM router, which handles the fallback.
    model: str = Field(default_factory=get_default_model)
    temperature: float = 0.7
    max_tokens: int = 150
    # Optional system prompt to set the behavior/role of the AI
    system_prompt: Optional[str] = None

class PromptResponse(BaseModel):
    response: str
    model: str # The actual model that was used
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost: float

class ModelInfo(BaseModel):
    id: str
    object: str
    created: int
    owned_by: str

class ModelsResponse(BaseModel):
    object: str
    data: List[ModelInfo]

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage MLflow experiment tracking."""
    # Enable auto-tracing for LiteLLM
    mlflow.litellm.autolog()
    
    # Set the experiment
    mlflow.set_experiment("llmops-new")
    
    yield
    
    # Cleanup resources if needed
    pass

# --- FastAPI Application Setup ---
app = FastAPI(
    title="LLMOps API",
    description="API for interacting with LLMs via LiteLLM's smart router.",
    lifespan=lifespan
)

# --- API Endpoints ---
@app.get("/")
async def root():
    """Root endpoint providing a welcome message."""
    return {"message": "LLMOps API is running!", "timestamp": datetime.now()}

@app.get("/health")
async def health_check():
    """Health check endpoint to verify service status."""
    return {"status": "healthy", "timestamp": datetime.now()}

@app.get("/debug")
async def debug_config():
    """Debug endpoint to show current configuration."""
    return {
        "litellm_url": os.getenv("LITELLM_URL", "http://litellm:8000"),
        "mlflow_uri": os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000"),
        "openai_client_base_url": str(client.base_url),
        "using_litellm_proxy": True,
        "timestamp": datetime.now()
    }

# Available models from LiteLLM proxy (fallbacks handled by proxy)
# Models: gpt-4o-primary, gemini-secondary, openrouter-fallback, smart-router
# smart-router has fallbacks: gemini-secondary -> openrouter-fallback

@app.post("/generate", response_model=PromptResponse)
@mlflow.trace(name="llm_generation", span_type=SpanType.LLM)
async def generate_text(prompt_request: PromptRequest):
    """Generate text using LiteLLM with automatic MLflow tracing."""
    print(f"DEBUG: Starting generate_text with model: {prompt_request.model}")
    print(f"DEBUG: Prompt: {prompt_request.prompt[:100]}")
    
    # Get the parent span created by the decorator
    parent_span = mlflow.get_current_active_span()
    print(f"DEBUG: Got parent span: {parent_span}")

    # Create child spans for each step
    with mlflow.start_span("input_processing") as span:
        span.add_event(SpanEvent("Processing input request", attributes={
            "model": prompt_request.model,
            "prompt_preview": prompt_request.prompt[:100]
        }))
        span.set_attributes({
            "request.model": prompt_request.model,
            "request.temperature": prompt_request.temperature,
            "request.max_tokens": prompt_request.max_tokens,
            "request.prompt": prompt_request.prompt[:500],  # First 500 chars
            "request.system_prompt": prompt_request.system_prompt[:500] if prompt_request.system_prompt else None,
            "request.has_system_prompt": bool(prompt_request.system_prompt)
        })

    try:
        # Use direct HTTP requests to LiteLLM proxy to avoid client compatibility issues
        with mlflow.start_span("llm_call") as span:
            print(f"DEBUG: About to send request to LiteLLM with model: {prompt_request.model}")
            
            # Build messages array - include system prompt if provided
            messages = []
            if prompt_request.system_prompt:
                messages.append({"role": "system", "content": prompt_request.system_prompt})
            messages.append({"role": "user", "content": prompt_request.prompt})
            
            span.add_event(SpanEvent("Sending request to LiteLLM proxy", attributes={
                "model": prompt_request.model,
                "has_system_prompt": bool(prompt_request.system_prompt)
            }))
            
            request_payload = {
                "model": prompt_request.model,
                "messages": messages,
                "temperature": prompt_request.temperature,
                "max_tokens": prompt_request.max_tokens
            }
            print(f"DEBUG: Request payload: {request_payload}")
            
            litellm_response = requests.post(
                f"{LITELLM_URL}/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer sk-1234"  # LiteLLM proxy requires any API key
                },
                json=request_payload
            )
            print(f"DEBUG: LiteLLM response status: {litellm_response.status_code}")
            print(f"DEBUG: LiteLLM response headers: {dict(litellm_response.headers)}")
            print(f"DEBUG: LiteLLM response text: {litellm_response.text[:500]}")
            
            litellm_response.raise_for_status()
            response_data = litellm_response.json()
            print(f"DEBUG: Parsed response data: {response_data}")
            
            span.add_event(SpanEvent("Received response from LiteLLM proxy"))

        with mlflow.start_span("output_processing") as span:
            span.add_event(SpanEvent("Processing LLM response"))
            # Extract details from the successful response
            completion_text = response_data["choices"][0]["message"]["content"]
            usage = response_data["usage"]
            actual_model = response_data["model"] or prompt_request.model
            
            # Cost calculation is handled by LiteLLM, using the documented method
            try:
                print(f"DEBUG: Calculating cost for model: {actual_model}")
                cost = completion_cost(
                    model=actual_model,
                    prompt=prompt_request.prompt,
                    completion=completion_text
                ) or 0.0
                print(f"DEBUG: Cost calculated successfully: {cost}")
            except Exception as e:
                print(f"DEBUG: Error calculating cost: {e}")
                cost = 0.0
            span.add_event(SpanEvent("Calculated cost", attributes={"cost": cost}))
            
            # Set attributes on the output processing span
            span.set_attributes({
                "response.model": actual_model,
                "response.completion_tokens": usage["completion_tokens"],
                "response.prompt_tokens": usage["prompt_tokens"],
                "response.total_tokens": usage["total_tokens"],
                "response.cost": cost,
                "response.completion_text": completion_text[:500]  # First 500 chars
            })

            # Also add cost to the main parent span for easy visibility
            if parent_span:
                parent_span.set_attribute("response.cost", cost)
        
        return PromptResponse(
            response=completion_text,
            model=actual_model,
            prompt_tokens=usage["prompt_tokens"],
            completion_tokens=usage["completion_tokens"],
            total_tokens=usage["total_tokens"],
            cost=cost
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=503, 
            detail=f"LLM request failed: {str(e)}"
        )

@app.get("/models", response_model=ModelsResponse)
async def list_models():
    """List all available models from the LiteLLM router."""
    try:
        response = requests.get(f"{LITELLM_URL}/models")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error fetching models: {e}")
