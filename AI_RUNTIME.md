# Phobos Local AI Runtime

Phobos uses a local Mistral security brain. Normal users do not configure an AI provider, API key, or model name.

## Runtime flow

```text
Phobos starts
     ↓
Detect hardware
     ↓
Select the strongest compatible Mistral profile
     ↓
Start the bundled/local inference runtime
     ↓
Acquire the selected model when needed
     ↓
Run the security brain locally
```

## Model selection

The setup manager prefers Mistral Small 3.2 24B and chooses a quantization based on available system memory and detected NVIDIA VRAM. On constrained machines it falls back to Mistral 7B so Phobos remains usable instead of failing because the preferred model does not fit.

The exact model is an implementation detail exposed for development diagnostics, not a normal user configuration requirement.

## First run

The first AI operation may require a model download. Setup state is stored under the user's local `.phobos` directory so subsequent launches do not repeat the acquisition step unnecessarily.

The future desktop installer should bundle the inference runtime beside the Phobos executable and use the same setup manager. That turns the current development behavior into the intended product behavior:

```text
Download Phobos → Install → Open → Scan
```

## Development overrides

For development and packaging work only, the following environment variables are supported:

- `PHOBOS_AI_MODEL` — override the hardware-selected model.
- `PHOBOS_AI_URL` — override the loopback runtime endpoint.
- `PHOBOS_AI_AUTOSTART` — disable automatic runtime startup.
- `PHOBOS_AI_AUTO_PULL` — disable automatic model acquisition.
- `PHOBOS_OLLAMA_BINARY` — point Phobos to a development Ollama executable.

These are intentionally not required for ordinary use.
