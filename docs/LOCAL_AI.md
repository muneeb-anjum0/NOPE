# NOPE Local AI

NOPE integrates local Qwen through a dedicated llama.cpp server container. Ollama is not used.

## Intended Model

- Model family: Qwen3 8B-class
- Quantization: Q4_K_M
- Expected local filename: `Qwen3-8B-Q4_K_M.gguf`
- Current host path: `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`
- Default in-container path for the next AI phase: `/models/Qwen3-8B-Q4_K_M.gguf`

The model file must not be committed to Git. `*.gguf` and `models/` are ignored.

## Model Directory

Set this in `.env` or shell:

```bash
NOPE_MODEL_DIR=D:/Desktop/Model
NOPE_QWEN_MODEL_FILE=Qwen3-8B-Q4_K_M.gguf
```

The directory is mounted read-only into `nope-ai` at `/models`.

## Core Mode Without AI

```bash
docker compose up --build -d
```

This starts NOPE without requiring a model.

## CPU AI Mode

```bash
docker compose -f docker-compose.yml -f docker-compose.ai-cpu.yml --profile ai-cpu up --build -d
```

CPU mode sets `NOPE_AI_PROVIDER=llama.cpp` and uses `NOPE_AI_GPU_LAYERS=0`.

## GPU AI Mode

```bash
docker compose -f docker-compose.yml -f docker-compose.ai-gpu.yml --profile ai-gpu up --build -d
```

GPU mode requests an NVIDIA GPU through Docker Compose device reservations.

## Endpoints

- Host debug endpoint: `http://localhost:8081`
- Internal endpoint: `http://nope-ai:8080`
- Health: `/health`
- Completion: `/completion`

## Security Notes

- The model mount is read-only.
- The service does not mount host secrets.
- The service has no Docker socket.
- It is not privileged.
- It receives focused finding evidence, not whole repositories.
- It has no shell/tool execution path from NOPE.

## Current Verification

The GGUF file exists at `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`, and `nvidia-smi` sees a 6 GB GTX 1060 Max-Q. Actual llama.cpp container loading, GPU VRAM use, and inference are still not verified.
