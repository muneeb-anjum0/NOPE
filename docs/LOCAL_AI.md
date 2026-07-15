# NOPE Local AI

NOPE integrates local Qwen through a dedicated llama.cpp server container. Ollama is not used.

## Intended Model

- Model family: Qwen3 8B-class
- Quantization: Q4_K_M
- Expected local filename: `Qwen3-8B-Q4_K_M.gguf`
- Current host path: `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`
- Default in-container path: `/models/Qwen3-8B-Q4_K_M.gguf`

The model file must not be committed to Git. `*.gguf` and `models/` are ignored.

## Model Directory

Set this in `.env` or shell:

```bash
NOPE_MODEL_HOST_DIR=D:/Desktop/Model
NOPE_MODEL_FILE=Qwen3-8B-Q4_K_M.gguf
NOPE_QWEN_GPU_LAYERS=28
NOPE_QWEN_GPU_MEMORY_TARGET_MB=5000
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

CPU mode sets `NOPE_AI_PROVIDER=llama.cpp` and uses `NOPE_QWEN_GPU_LAYERS=0`.

## GPU AI Mode

```bash
docker compose -f docker-compose.yml -f docker-compose.ai-gpu.yml --profile ai-gpu up --build -d
```

GPU mode requests an NVIDIA GPU through Docker Compose device reservations. The verified GTX 1060 Max-Q setting is `NOPE_QWEN_GPU_LAYERS=28`, which loads Qwen through CUDA while keeping measured VRAM below the 5 GB target.

## Endpoints

- Host debug endpoint: `http://localhost:8081`
- Internal endpoint: `http://nope-ai:8080`
- Health: `/health`
- Completion: `/completion`
- OpenAI-compatible chat completion: `/v1/chat/completions`

## Security Notes

- The model mount is read-only.
- The service does not mount host secrets.
- The service has no Docker socket.
- It is not privileged.
- It receives focused finding evidence, not whole repositories.
- It has no shell/tool execution path from NOPE.

## Current Verification

Verified on 2026-07-15:

- GGUF file exists at `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf`.
- GPU is `NVIDIA GeForce GTX 1060 with Max-Q Design`, 6144 MiB total.
- `ghcr.io/ggml-org/llama.cpp:server-cuda` loads the model in `nope-ai`.
- Stable GPU setting is `NOPE_QWEN_GPU_LAYERS=28`.
- Measured VRAM at 28 layers is about 4041-4049 MiB, below the 5000 MiB Phase 5 ceiling.
- `NOPE_QWEN_GPU_LAYERS=30` failed to fit in available GPU memory, so 28 is the final verified setting.
- Direct `/completion`, structured `/v1/chat/completions`, API health, and NOPE finding explanation all succeeded.
- With `nope-ai` stopped, repository scan `scan_443bb3dbdb9b4568` still completed with 7 deterministic findings and recorded Qwen review as failed.
