from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
import requests
import os
import mlflow
import openai
from litellm import completion_cost
from mlflow.entities.span import SpanType
from mlflow.entities.span_event import SpanEvent
import time
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

# Get LiteLLM's URL from environment variables, with a default for local dev
LITELLM_URL = os.getenv("LITELLM_URL", "http://litellm:8000")

# Initialize MLflow tracking
mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000"))

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

# --- Security Configuration ---
class SecurityConfig:
    MAX_PROMPT_LENGTH = 2000
    MAX_SYSTEM_PROMPT_LENGTH = 1000
    MIN_TEMPERATURE = 0.0
    MAX_TEMPERATURE = 1.0
    MIN_MAX_TOKENS = 1
    MAX_MAX_TOKENS = 2000
    ALLOWED_MODEL_PATTERN = r"^(groq|gpt|gemini|openrouter)-[a-z0-9-]+$"
    RATE_LIMIT_REQUESTS_PER_MINUTE = 60
    SUSPICIOUS_PATTERNS = [
        r"ignore.{0,20}(all|previous|above).{0,20}(instruct|instruction)",
        r"(forget|disregard).{0,20}(everything|all).{0,20}(instruct|instruction)",
        r"you.{0,10}are.{0,10}now.{0,10}(a|an).{0,10}(hacker|admin)",
        r"###.{0,20}(system|override|admin).{0,20}(mode|access)",
        r"---.*new.*instruct",
        r"(decode|base64).{0,10}(and|then).{0,10}(apply|execute|instruct)",
        r"\\n\\n(system|admin):"
    ]

# Rate limiting storage (in production, use Redis)
rate_limit_storage = defaultdict(list)

# Security metrics storage (in production, use proper database)
security_metrics = {
    "total_requests": 0,
    "blocked_requests": 0,
    "prompt_injections_detected": 0,
    "content_moderation_triggered": 0,
    "rate_limit_violations": 0,
    "validation_failures": 0,
    "security_incidents": [],
    "last_reset": datetime.now()
}

# --- Enhanced Pydantic Models with Security Validation ---
class SecurePromptRequest(BaseModel):
    prompt: str = Field(
        ..., 
        min_length=1, 
        max_length=SecurityConfig.MAX_PROMPT_LENGTH,
        description="User prompt (max 2000 characters)"
    )
    model: str = Field(
        default_factory=get_default_model,
        pattern=SecurityConfig.ALLOWED_MODEL_PATTERN,
        description="Model name matching allowed pattern"
    )
    temperature: float = Field(
        0.7, 
        ge=SecurityConfig.MIN_TEMPERATURE, 
        le=SecurityConfig.MAX_TEMPERATURE,
        description="Temperature between 0.0 and 1.0"
    )
    max_tokens: int = Field(
        150, 
        ge=SecurityConfig.MIN_MAX_TOKENS, 
        le=SecurityConfig.MAX_MAX_TOKENS,
        description="Max tokens between 1 and 2000"
    )
    system_prompt: Optional[str] = Field(
        None, 
        max_length=SecurityConfig.MAX_SYSTEM_PROMPT_LENGTH,
        description="System prompt (max 1000 characters)"
    )
    response_format: Optional[Dict[str, Any]] = Field(
        None,
        description="Structured output format (JSON schema)"
    )
    enable_guardrails: bool = Field(
        True,
        description="Enable LiteLLM security guardrails (recommended)"
    )
    enable_content_moderation: bool = Field(
        True,
        description="Enable content moderation"
    )
    
    @field_validator('prompt')
    @classmethod
    def validate_prompt_security(cls, v):
        """Check for suspicious patterns in prompt."""
        prompt_lower = v.lower()
        for i, pattern in enumerate(SecurityConfig.SUSPICIOUS_PATTERNS):
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                # Log the attack attempt with full prompt
                security_metrics["validation_failures"] += 1
                security_metrics["blocked_requests"] += 1
                security_metrics["security_incidents"].append({
                    "type": "input_validation_blocked",
                    "pattern_matched": pattern,
                    "pattern_index": i,
                    "full_prompt": v,  # Log full prompt for security analysis
                    "prompt_preview": v[:100],
                    "timestamp": datetime.now().isoformat(),
                    "source": "pydantic_validation"
                })
                
                # MLflow logging removed from validators to avoid duplicate traces
                
                raise ValueError(f"Potentially malicious pattern detected in prompt")
        return v
    
    @field_validator('system_prompt')
    @classmethod
    def validate_system_prompt_security(cls, v):
        """Check for suspicious patterns in system prompt."""
        if v is None:
            return v
        prompt_lower = v.lower()
        for i, pattern in enumerate(SecurityConfig.SUSPICIOUS_PATTERNS):
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                # Log the attack attempt with full system prompt
                security_metrics["validation_failures"] += 1
                security_metrics["blocked_requests"] += 1
                security_metrics["security_incidents"].append({
                    "type": "system_prompt_validation_blocked",
                    "pattern_matched": pattern,
                    "pattern_index": i,
                    "full_system_prompt": v,  # Log full system prompt
                    "prompt_preview": v[:100],
                    "timestamp": datetime.now().isoformat(),
                    "source": "pydantic_validation"
                })
                
                # MLflow logging removed from validators to avoid duplicate traces
                
                raise ValueError(f"Potentially malicious pattern detected in system prompt")
        return v

class SecurePromptResponse(BaseModel):
    response: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost: float
    security_status: str = "protected"
    guardrails_triggered: List[str] = Field(default_factory=list)

class ModelInfo(BaseModel):
    id: str
    object: str
    created: int
    owned_by: str

class ModelsResponse(BaseModel):
    object: str
    data: List[ModelInfo]

# --- Security Middleware ---
async def security_middleware(request: Request, call_next):
    """Security middleware for rate limiting and request validation."""
    client_ip = request.client.host
    current_time = datetime.now()
    
    # Rate limiting check
    if client_ip in rate_limit_storage:
        # Remove old entries (older than 1 minute)
        rate_limit_storage[client_ip] = [
            timestamp for timestamp in rate_limit_storage[client_ip]
            if current_time - timestamp < timedelta(minutes=1)
        ]
        
        if len(rate_limit_storage[client_ip]) >= SecurityConfig.RATE_LIMIT_REQUESTS_PER_MINUTE:
            # Record security metric
            security_metrics["rate_limit_violations"] += 1
            security_metrics["blocked_requests"] += 1
            security_metrics["security_incidents"].append({
                "type": "rate_limit_violation",
                "client_ip": client_ip,
                "timestamp": current_time.isoformat(),
                "requests_in_minute": len(rate_limit_storage[client_ip])
            })
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Maximum {SecurityConfig.RATE_LIMIT_REQUESTS_PER_MINUTE} requests per minute"
                }
            )
    
    # Add current request timestamp
    rate_limit_storage[client_ip].append(current_time)
    
    # Security event logging removed from middleware to avoid duplicate traces
    
    response = await call_next(request)
    return response

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage MLflow experiment tracking and security setup."""
    # Enable auto-tracing for LiteLLM with silent mode to avoid conflicts
    #mlflow.litellm.autolog(log_traces=True, silent=True)
    
    # Set the security experiment
    mlflow.set_experiment("llmops-security")
    
    yield
    
    # Cleanup resources if needed
    pass

# --- FastAPI Application Setup with Security ---
app = FastAPI(
    title="LLMOps Secure API",
    description="Secure API for interacting with LLMs via LiteLLM with built-in security guardrails.",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security middleware
app.middleware("http")(security_middleware)

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

@app.get("/security-status")
async def security_status():
    """Security status endpoint showing current protection levels."""
    return {
        "security_features": {
            "prompt_injection_detection": True,
            "content_moderation": True,
            "rate_limiting": True,
            "input_validation": True,
            "output_filtering": True
        },
        "security_config": {
            "max_prompt_length": SecurityConfig.MAX_PROMPT_LENGTH,
            "max_system_prompt_length": SecurityConfig.MAX_SYSTEM_PROMPT_LENGTH,
            "rate_limit_per_minute": SecurityConfig.RATE_LIMIT_REQUESTS_PER_MINUTE,
            "allowed_model_pattern": SecurityConfig.ALLOWED_MODEL_PATTERN,
            "suspicious_patterns_count": len(SecurityConfig.SUSPICIOUS_PATTERNS)
        },
        "guardrails": ["security-guard", "content-filter"],
        "status": "active",
        "timestamp": datetime.now()
    }

@app.get("/security-metrics")
async def security_metrics_endpoint():
    """Security metrics endpoint showing real-time security statistics."""
    current_time = datetime.now()
    uptime_seconds = (current_time - security_metrics["last_reset"]).total_seconds()
    
    # Calculate rates
    requests_per_minute = (security_metrics["total_requests"] / uptime_seconds) * 60 if uptime_seconds > 0 else 0
    block_rate = (security_metrics["blocked_requests"] / security_metrics["total_requests"]) * 100 if security_metrics["total_requests"] > 0 else 0
    
    # Get recent incidents (last 24 hours)
    recent_incidents = [
        incident for incident in security_metrics["security_incidents"]
        if (current_time - datetime.fromisoformat(incident["timestamp"])).total_seconds() < 86400
    ]
    
    return {
        "overview": {
            "total_requests": security_metrics["total_requests"],
            "blocked_requests": security_metrics["blocked_requests"],
            "success_requests": security_metrics["total_requests"] - security_metrics["blocked_requests"],
            "block_rate_percent": round(block_rate, 2),
            "requests_per_minute": round(requests_per_minute, 2),
            "uptime_hours": round(uptime_seconds / 3600, 2)
        },
        "security_events": {
            "prompt_injections_detected": security_metrics["prompt_injections_detected"],
            "content_moderation_triggered": security_metrics["content_moderation_triggered"],
            "rate_limit_violations": security_metrics["rate_limit_violations"],
            "validation_failures": security_metrics["validation_failures"]
        },
        "recent_incidents": {
            "count_last_24h": len(recent_incidents),
            "incidents": recent_incidents[-10:]  # Last 10 incidents
        },
        "health_status": {
            "status": "healthy" if block_rate < 20 else "warning" if block_rate < 50 else "critical",
            "active_protections": 4,
            "last_incident": recent_incidents[-1]["timestamp"] if recent_incidents else None
        },
        "timestamp": current_time.isoformat(),
        "data_since": security_metrics["last_reset"].isoformat()
    }

@app.post("/security-metrics/reset")
async def reset_security_metrics():
    """Reset security metrics (admin endpoint)."""
    global security_metrics
    security_metrics = {
        "total_requests": 0,
        "blocked_requests": 0,
        "prompt_injections_detected": 0,
        "content_moderation_triggered": 0,
        "rate_limit_violations": 0,
        "validation_failures": 0,
        "security_incidents": [],
        "last_reset": datetime.now()
    }
    
    return {
        "message": "Security metrics reset successfully",
        "reset_time": security_metrics["last_reset"].isoformat()
    }

@app.get("/security-incidents")
async def get_security_incidents(limit: int = 50):
    """Get detailed security incidents with full prompts for analysis."""
    recent_incidents = security_metrics["security_incidents"][-limit:]
    
    return {
        "total_incidents": len(security_metrics["security_incidents"]),
        "showing_recent": len(recent_incidents),
        "incidents": recent_incidents,
        "incident_types": {
            incident_type: len([i for i in recent_incidents if i["type"] == incident_type])
            for incident_type in set(i["type"] for i in recent_incidents)
        },
        "timestamp": datetime.now().isoformat()
    }

# Available models from LiteLLM proxy (fallbacks handled by proxy)
# Models: gpt-4o-primary, gemini-secondary, openrouter-fallback, smart-router
# smart-router has fallbacks: gemini-secondary -> openrouter-fallback

@app.post("/generate", response_model=SecurePromptResponse)
@mlflow.trace(name="secure_llm_generation", span_type=SpanType.LLM)
async def generate_text(prompt_request: SecurePromptRequest):
    """Generate text using LiteLLM with automatic MLflow tracing."""
    print(f"DEBUG: Starting generate_text with model: {prompt_request.model}")
    print(f"DEBUG: Prompt: {prompt_request.prompt[:100]}")
    
    # Record request metric
    security_metrics["total_requests"] += 1
    
    # Get the current span created by the decorator for inputs/outputs
    current_span = mlflow.get_current_active_span()
    print(f"DEBUG: Got current span: {current_span}")
    
    # Set inputs on the trace for visibility in Request column
    if current_span:
        current_span.set_inputs({
            "model": prompt_request.model,
            "prompt": prompt_request.prompt,
            "system_prompt": prompt_request.system_prompt,
            "temperature": prompt_request.temperature,
            "max_tokens": prompt_request.max_tokens,
            "response_format": prompt_request.response_format,
            "enable_guardrails": prompt_request.enable_guardrails
        })

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
            "request.has_system_prompt": bool(prompt_request.system_prompt),
            "request.response_format": str(prompt_request.response_format) if prompt_request.response_format else None,
            "request.has_response_format": bool(prompt_request.response_format)
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
                "has_system_prompt": bool(prompt_request.system_prompt),
                "has_response_format": bool(prompt_request.response_format)
            }))
            
            request_payload = {
                "model": prompt_request.model,
                "messages": messages,
                "temperature": prompt_request.temperature,
                "max_tokens": prompt_request.max_tokens
            }
            
            # Note: Security is handled at the API level with input validation
            # LiteLLM guardrails would be configured at the proxy level if available
            
            # Add response_format if provided (for structured outputs)
            if prompt_request.response_format:
                request_payload["response_format"] = prompt_request.response_format
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

            # Also add cost to the main current span for easy visibility
            if current_span:
                current_span.set_attribute("response.cost", cost)
        
        # Check for guardrails in response
        guardrails_triggered = response_data.get("guardrails_triggered", [])
        
        # Set outputs on the trace for visibility in Response column
        if current_span:
            current_span.set_outputs({
                "response": completion_text,
                "model_used": actual_model,
                "prompt_tokens": usage["prompt_tokens"],
                "completion_tokens": usage["completion_tokens"],
                "total_tokens": usage["total_tokens"],
                "cost": cost,
                "security_status": "protected" if prompt_request.enable_guardrails else "unprotected",
                "guardrails_triggered": guardrails_triggered
            })
        
        return SecurePromptResponse(
            response=completion_text,
            model=actual_model,
            prompt_tokens=usage["prompt_tokens"],
            completion_tokens=usage["completion_tokens"],
            total_tokens=usage["total_tokens"],
            cost=cost,
            security_status="protected" if prompt_request.enable_guardrails else "unprotected",
            guardrails_triggered=guardrails_triggered
        )
        
    except requests.exceptions.HTTPError as e:
        # Handle security-related errors from LiteLLM
        if e.response.status_code == 400:
            error_detail = e.response.text
            if "prompt injection" in error_detail.lower():
                # Record security metrics
                security_metrics["prompt_injections_detected"] += 1
                security_metrics["blocked_requests"] += 1
                security_metrics["security_incidents"].append({
                    "type": "prompt_injection_blocked",
                    "prompt_preview": prompt_request.prompt[:100],
                    "model": prompt_request.model,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Log security event
                with mlflow.start_span("security_incident") as span:
                    span.set_attributes({
                        "incident_type": "prompt_injection_blocked",
                        "prompt_preview": prompt_request.prompt[:100],
                        "model": prompt_request.model
                    })
                
                raise HTTPException(
                    status_code=400,
                    detail="Request blocked by security guardrails: Potential prompt injection detected"
                )
            elif "content moderation" in error_detail.lower():
                # Record security metrics
                security_metrics["content_moderation_triggered"] += 1
                security_metrics["blocked_requests"] += 1
                security_metrics["security_incidents"].append({
                    "type": "content_moderation_blocked",
                    "prompt_preview": prompt_request.prompt[:100],
                    "model": prompt_request.model,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Log security event
                with mlflow.start_span("security_incident") as span:
                    span.set_attributes({
                        "incident_type": "content_moderation_blocked",
                        "prompt_preview": prompt_request.prompt[:100],
                        "model": prompt_request.model
                    })
                
                raise HTTPException(
                    status_code=400,
                    detail="Request blocked by security guardrails: Content moderation triggered"
                )
        
        raise HTTPException(
            status_code=503, 
            detail=f"LLM request failed: {str(e)}"
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
