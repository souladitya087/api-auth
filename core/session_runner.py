import shlex
from typing import Any, Dict, Optional
import httpx
from pydantic import BaseModel, Field


class Persona(BaseModel):
    name: str
    role: str = "user"  # "user", "admin", "anonymous"
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    # Owned resources to test object substitution (e.g. {"doc_id": "101", "user_id": "user_a"})
    owned_resources: Dict[str, Any] = Field(default_factory=dict)


class RequestExecutionResult(BaseModel):
    persona_name: str
    url: str
    method: str
    headers_sent: Dict[str, str]
    status_code: int
    response_body: str
    response_headers: Dict[str, str]
    elapsed_ms: float
    curl_command: str


class SessionRunner:
    """
    Manages asynchronous HTTP sessions across distinct security personas.
    """

    def __init__(self, base_url: str, timeout_seconds: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def format_curl(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        data: Optional[Dict[str, Any]] = None,
    ) -> str:
        parts = ["curl", "-X", method, shlex.quote(url)]
        for k, v in headers.items():
            parts.extend(["-H", shlex.quote(f"{k}: {v}")])
        if data:
            import json
            parts.extend(["-H", shlex.quote("Content-Type: application/json")])
            parts.extend(["--data", shlex.quote(json.dumps(data))])
        return " ".join(parts)

    async def execute_request(
        self,
        persona: Persona,
        endpoint_path: str,
        method: str,
        path_params: Optional[Dict[str, Any]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> RequestExecutionResult:
        # Interpolate path params
        resolved_path = endpoint_path
        if path_params:
            for k, v in path_params.items():
                resolved_path = resolved_path.replace(f"{{{k}}}", str(v))

        full_url = f"{self.base_url}{resolved_path}"
        headers = dict(persona.headers)

        curl_cmd = self.format_curl(method, full_url, headers, json_body)

        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False) as client:
            try:
                response = await client.request(
                    method=method,
                    url=full_url,
                    headers=headers,
                    cookies=persona.cookies,
                    params=query_params,
                    json=json_body,
                )
                return RequestExecutionResult(
                    persona_name=persona.name,
                    url=full_url,
                    method=method,
                    headers_sent=headers,
                    status_code=response.status_code,
                    response_body=response.text[:2048],  # Capture snippet for safety/analysis
                    response_headers=dict(response.headers),
                    elapsed_ms=response.elapsed.total_seconds() * 1000.0,
                    curl_command=curl_cmd,
                )
            except httpx.RequestError as exc:
                return RequestExecutionResult(
                    persona_name=persona.name,
                    url=full_url,
                    method=method,
                    headers_sent=headers,
                    status_code=0,
                    response_body=f"Connection Error: {str(exc)}",
                    response_headers={},
                    elapsed_ms=0.0,
                    curl_command=curl_cmd,
                )
