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
    openwebui,
    qdrant,
    ray,
    vllm,
    weaviate,
)

ALL_CHECKERS = [
    ollama, n8n, openwebui, vllm, langfuse, comfyui, ray, dify, qdrant,
    anythingllm, jupyter, gradio_langflow, flowise, chroma, weaviate, mcp,
]
