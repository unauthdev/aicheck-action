"""Checker registry. Each module exposes detect(facts) -> list[Finding]."""

from . import (
    aig_fingerprints,
    anythingllm,
    autogen_studio,
    chroma,
    comfyui,
    crewai,
    dify,
    flowise,
    gradio_langflow,
    jupyter,
    langfuse,
    langserve,
    mcp,
    milvus,
    n8n,
    ollama,
    openai_compat,
    openclaw,
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
    langserve, openclaw, openhands, autogen_studio, crewai, redis, milvus,
    openai_compat,  # after product checkers — generic /v1/models leftover
    aig_fingerprints,  # additive GET fingerprints (skip when primary already hit)
]
