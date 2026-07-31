"""
gateway.py — the "model" behind the resource server.

Deliberately NOT a real model: a deterministic stub, so the mechanism is about
*access control* (who may call which model, with what token), not inference. It
takes a prompt and returns a canned completion plus a token count, the shape a
real inference API returns. Swapping in a real backend (or a local model) would
not change any of the authentication/authorization code around it — which is
the point of putting the gateway in front.
"""

# The catalog the gateway serves. A client is separately restricted to a subset
# of these via its `allowed_models` (authorization is per-client, not per-token).
AVAILABLE_MODELS = {
    "gpt-sim": "deterministic chat stand-in",
    "embed-sim": "deterministic embedding stand-in",
}


def invoke_model(model: str, prompt: str) -> dict:
    words = prompt.split()
    output = f"[{model}] received {len(words)} words; echo: {prompt[:120]}"
    return {
        "model": model,
        "output": output,
        "usage": {"prompt_tokens": len(words), "completion_tokens": len(output.split())},
    }
