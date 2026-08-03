"""Checker registry. Each module exposes detect(facts) -> list[Finding]."""

from . import (
    anythingllm,
    chroma,
    comfyui,
    dify,
    flowise,
    gradio_langflow,
    jupyter,
    langfuse,
    mcp,
    n8n,
    ollama,
    openai_compat,
    openhands,
    openwebui,
    qdrant,
    ray,
    redis,
    vllm,
    weaviate,
)

ALL_CHECKERS = [
    ollama, n8n, openwebui, vllm, langfuse, comfyui, ray, dify, qdrant,
    anythingllm, jupyter, gradio_langflow, flowise, chroma, weaviate, mcp,
    openhands, redis,
    openai_compat,  # after product checkers — generic /v1/models leftover
]
