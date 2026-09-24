import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field


class EndpointParameter(BaseModel):
    name: str
    in_location: str = Field(alias="in")
    required: bool = False
    param_type: str = "string"
    description: Optional[str] = None
    example: Optional[Any] = None

    class Config:
        populate_by_name = True


class APIEndpoint(BaseModel):
    path: str
    method: str
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    parameters: List[EndpointParameter] = Field(default_factory=list)
    has_path_params: bool = False
    is_admin_candidate: bool = False
    requires_auth: bool = True

    def get_path_param_names(self) -> List[str]:
        return [p.name for p in self.parameters if p.in_location == "path"]


class OpenAPISpecParser:
    """
    Parses OpenAPI 3.0.x and Swagger 2.0 specifications to extract
    auditable endpoints and their parameter schemas.
    """

    ADMIN_KEYWORDS = {"admin", "manage", "system", "internal", "root", "privileged"}

    def __init__(self, spec_path: str):
        self.spec_path = Path(spec_path)
        self.raw_spec: Dict[str, Any] = self._load_spec()
        self.base_url: str = self._extract_base_url()
        self.endpoints: List[APIEndpoint] = self._parse_endpoints()

    def _load_spec(self) -> Dict[str, Any]:
        if not self.spec_path.exists():
            raise FileNotFoundError(f"OpenAPI spec not found at: {self.spec_path}")

        content = self.spec_path.read_text(encoding="utf-8")
        if self.spec_path.suffix in [".yaml", ".yml"]:
            return yaml.safe_load(content)
        return json.loads(content)

    def _extract_base_url(self) -> str:
        # OpenAPI 3.x
        if "servers" in self.raw_spec and self.raw_spec["servers"]:
            return self.raw_spec["servers"][0].get("url", "/")
        # Swagger 2.0
        host = self.raw_spec.get("host", "")
        base_path = self.raw_spec.get("basePath", "")
        schemes = self.raw_spec.get("schemes", ["http"])
        if host:
            return f"{schemes[0]}://{host}{base_path}"
        return base_path or "/"

    def _is_admin_endpoint(self, path: str, tags: List[str], summary: str) -> bool:
        lowered_path = path.lower()
        lowered_summary = (summary or "").lower()
        lowered_tags = [t.lower() for t in tags]

        for keyword in self.ADMIN_KEYWORDS:
            if f"/{keyword}" in lowered_path or keyword in lowered_summary:
                return True
            if any(keyword in tag for tag in lowered_tags):
                return True
        return False

    def _parse_endpoints(self) -> List[APIEndpoint]:
        endpoints: List[APIEndpoint] = []
        paths = self.raw_spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            common_params = path_item.get("parameters", [])

            for method in ["get", "post", "put", "delete", "patch"]:
                if method not in path_item:
                    continue

                operation = path_item[method]
                if not isinstance(operation, dict):
                    continue

                op_params = operation.get("parameters", [])
                all_params_data = common_params + op_params

                parsed_params: List[EndpointParameter] = []
                for p in all_params_data:
                    if "$ref" in p:
                        continue  # Skipping unresolved external refs for baseline
                    param_schema = p.get("schema", {})
                    param_type = param_schema.get("type", p.get("type", "string"))
                    example = p.get("example") or param_schema.get("example")

                    parsed_params.append(
                        EndpointParameter(
                            name=p.get("name", ""),
                            in_location=p.get("in", "query"),
                            required=p.get("required", False),
                            param_type=param_type,
                            description=p.get("description"),
                            example=example,
                        )
                    )

                # Path params detection via regex e.g. {id}
                path_param_placeholders = re.findall(r"\{([a-zA-Z0-9_]+)\}", path)
                for ph in path_param_placeholders:
                    if not any(p.name == ph and p.in_location == "path" for p in parsed_params):
                        parsed_params.append(
                            EndpointParameter(
                                name=ph,
                                in_location="path",
                                required=True,
                                param_type="string",
                            )
                        )

                tags = operation.get("tags", [])
                summary = operation.get("summary", "")
                is_admin = self._is_admin_endpoint(path, tags, summary)
                has_path_params = any(p.in_location == "path" for p in parsed_params)

                # Public auth endpoints like /login or /register do not require authorization checks
                is_auth_route = any(k in path.lower() for k in ["/login", "/register", "/token", "/health"])

                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get("operationId"),
                    summary=summary,
                    tags=tags,
                    parameters=parsed_params,
                    has_path_params=has_path_params,
                    is_admin_candidate=is_admin,
                    requires_auth=not is_auth_route,
                )
                endpoints.append(endpoint)

        return endpoints
