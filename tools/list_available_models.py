#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

PROVIDER_PATHS = {
    "openai": "models",
    "anthropic": "models",
    "gemini": "models",
    "antigravity": "antigravity/models",
}

PROVIDER_KEY_ENVS = {
    "openai": "SWEDEAPI_API_KEY_OPENAI",
    "anthropic": "SWEDEAPI_API_KEY_ANTI",
    "gemini": "SWEDEAPI_API_KEY_ANTI",
    "antigravity": "SWEDEAPI_API_KEY_ANTI",
}


def pick_api_key(provider: str, explicit: str | None) -> tuple[str, str]:
    if explicit:
        return explicit, "--api-key"

    candidates = [PROVIDER_KEY_ENVS.get(provider, "")]
    candidates.extend(["SWEDEAPI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN"])
    for env_name in candidates:
        if env_name and os.getenv(env_name):
            return os.environ[env_name], env_name
    raise SystemExit(
        f"missing API key: set {PROVIDER_KEY_ENVS.get(provider, 'SWEDEAPI_API_KEY')} or pass --api-key"
    )


def fetch_models(base_url: str, path: str, api_key: str) -> dict:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = Request(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": "swedeapi-model-list/1.0",
        },
    )
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_model_ids(payload: object) -> list[str]:
    if isinstance(payload, dict):
        data = payload.get("data", payload)
        if isinstance(data, list):
            models = []
            for item in data:
                if isinstance(item, str):
                    models.append(item)
                elif isinstance(item, dict):
                    model_id = item.get("id") or item.get("model") or item.get("name")
                    if model_id:
                        models.append(str(model_id))
            return models
    if isinstance(payload, list):
        return [str(item) for item in payload]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description="List available models from swedeapi")
    parser.add_argument("provider", choices=sorted(PROVIDER_PATHS), help="LLM provider")
    parser.add_argument(
        "--base-url",
        default=os.getenv("SWEDEAPI_BASE_URL", "http://localhost:8080/v1/"),
        help="swedeapi base URL (default: SWEDEAPI_BASE_URL or http://localhost:8080/v1/)",
    )
    parser.add_argument(
        "--path",
        help="override request path (default depends on provider)",
    )
    parser.add_argument("--api-key", help="override API key")
    parser.add_argument("--json", action="store_true", help="print raw JSON response")
    args = parser.parse_args()

    path = args.path or PROVIDER_PATHS[args.provider]
    api_key, key_source = pick_api_key(args.provider, args.api_key)

    try:
        payload = fetch_models(args.base_url, path, api_key)
    except HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        sys.stderr.write(f"HTTP {err.code} from {err.url}\n{body}\n")
        return 1
    except URLError as err:
        sys.stderr.write(f"request failed: {err}\n")
        return 1

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    models = extract_model_ids(payload)
    print(f"provider: {args.provider}")
    print(f"base_url: {args.base_url}")
    print(f"path: {path}")
    print(f"api_key_source: {key_source}")
    print(f"count: {len(models)}")
    for model in models:
        print(model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
