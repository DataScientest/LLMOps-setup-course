# LLMOps Setup Course

This repository demonstrates an LLM application with model fallback, monitoring, and testing.

## Architecture

- **FastAPI Application**: REST API for LLM interactions with cascade fallback
- **LiteLLM Proxy**: Unified interface for multiple LLM providers (OpenAI, Gemini, OpenRouter)
- **MLflow**: Experiment tracking and prompt tracing

## Prerequisites

- Docker and Docker Compose
- uv
- API keys for:
  - Groq (required for the primary Qwen model)
  - OpenAI, Gemini, and OpenRouter (optional routes)

## Quick Start

1. Setup environment:
   ```bash
   cp env.example .env
   # Edit .env with your API keys
   uv sync --frozen
   ```

2. Start services:
   ```bash
   docker compose up -d --build --wait
   ```

3. Access services:
   - API: http://localhost:8000
   - LiteLLM: http://localhost:8001
   - MLflow UI: http://localhost:5001

## API Endpoints

### Text Generation
```http
POST /generate
Content-Type: application/json

{
  "prompt": "Your prompt here",
  "model": "groq-qwen-primary",
  "temperature": 0.7
}
```

### Available Models
```http
GET /models
```

### Health Check
```http
GET /health
```

## Model Fallback Strategy

1. **Primary**: `groq-qwen-primary` (`qwen/qwen3.6-27b`)
2. **Fallback**: `groq-gpt-oss-backup` (`openai/gpt-oss-20b`)

The other provider routes remain available explicitly when their keys are configured.

## Monitoring with MLflow

All LLM calls are tracked with:
- Input/Output parameters
- Token usage and latency
- Success/Failure status
- Request metadata and trace status

Access the MLflow UI at `http://localhost:5001`

## Project Structure

```
.
├── docker-compose.yml      # Service definitions
├── litellm-config.yaml    # LiteLLM model configuration
├── env.example            # Template for environment variables
├── pyproject.toml         # Python dependencies managed by uv
├── uv.lock                # Validated dependency lock
├── tests/                 # Integration tests
├── mlflow-data/           # MLflow experiment data
└── src/
    └── api/               # FastAPI application
        ├── main.py        # API endpoints
        └── Dockerfile     # API container setup
```

## Development

### Running Tests
Tests run through the locked uv environment:
```bash
uv run --frozen pytest
```

### Stopping Services
```bash
docker compose down
```

### Viewing Logs
```bash
docker compose logs -f
```

## Data Persistence
- MLflow data: `./mlflow-data`
- Test coverage reports: `./htmlcov`

## Makefile

The Makefile provides a set of commands to manage the environment and run tests. Here are the available commands:

> Note: `jq` is required to parse the API responses.

```sh
# Check API health
make api-test

# List available models
make api-models

# Generate text with fallback model
make api-generate PROMPT="What is the capital of France?"

# Generate text specifically with Gemini
make api-generate-gemini PROMPT="Explain quantum computing in simple terms"
```
