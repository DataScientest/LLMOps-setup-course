# 🧪 Tests Suite

This directory contains comprehensive test scripts for the LLMOps security stack, focusing on cache functionality and system performance.

## 📂 Test Scripts

### 🎯 Core Cache Tests

#### `test-cache-with-logs.sh`
**Advanced cache demonstration with log verification**
- Tests both exact and semantic cache
- Verifies cache hits in API logs
- Shows detailed cache behavior analysis

#### `test-cache-performance.sh`
**Performance benchmark for cache systems**
- Measures response times with/without cache
- Calculates speed improvements
- Compares exact vs semantic cache performance
- Requires `bc` calculator (install with `brew install bc` on macOS)

### 🔍 Comprehensive Tests

#### `test-comprehensive.sh`
**Complete system functionality test**
- Authentication verification
- API endpoint testing
- Cache functionality validation
- MLflow tracing verification
- Infrastructure health checks

#### `test-semantic-cache.sh`
**Detailed semantic cache analysis**
- Tests semantic similarity detection
- Validates cache threshold behavior
- Demonstrates multilingual cache support

## 🚀 Running Tests

### Quick Start
```bash
# Run all tests via Makefile
make -f Makefile.curl test-cache-with-logs
make -f Makefile.curl test-cache-performance
make -f Makefile.curl test-comprehensive

# Or run scripts directly
./tests/test-cache-with-logs.sh
./tests/test-cache-performance.sh
```

### Prerequisites
- Docker stack must be running: `docker compose up -d`
- All services healthy (check with `make -f Makefile.curl status`)
- `jq`, `curl`, and `bc` installed on system

## 📊 Expected Results

### Exact Cache
```bash
✅ First call: ~2-4s (calls LLM)
⚡ Second call: ~0.1-0.3s (cache hit)
📈 Speed improvement: 85-95%
```

### Semantic Cache
```bash  
✅ First call: ~2-4s (calls LLM + creates embedding)
⚡ Similar call: ~0.5-1s (semantic cache hit)
📈 Speed improvement: 60-80%
```

## 🔧 Configuration

Cache thresholds can be adjusted in `src/api/routers/llm.py`:
- **Exact threshold**: 1.0 (perfect match)
- **Semantic threshold**: 0.70 (similarity score)

## 🐛 Troubleshooting

### Common Issues

1. **Authentication Failed**
   ```bash
   # Check if API is running
   curl --fail http://localhost:8000/system/health
   ```

2. **Cache Not Working**
   ```bash
   # Clear cache and retry
   make -f Makefile.curl clear-cache
   ```

3. **Semantic Cache Not Triggering**
   - Check TEI service: `make -f Makefile.curl check-tei`
   - Verify Qdrant: `make -f Makefile.curl check-qdrant`
   - Adjust similarity threshold if needed

### Log Verification
Check cache hits in API logs:
```bash
docker logs llmops-setup-course-api-1 --tail=20 | grep -E "(Exact cache hit|Semantic cache hit)"
```

## 🔗 Related Files

- `Makefile.curl` - Test automation commands
- `docker-compose.yml` - Infrastructure configuration
- `src/api/cache/semantic_cache.py` - Cache implementation
- `src/api/routers/llm.py` - API cache integration
