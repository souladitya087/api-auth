import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from core.spec_parser import APIEndpoint, OpenAPISpecParser
from core.session_runner import Persona, RequestExecutionResult, SessionRunner


class AuditFinding(BaseModel):
    title: str
    vulnerability_type: str  # "BOLA", "BFLA", "UNAUTHENTICATED_ACCESS"
    owasp_id: str            # "API1:2023", "API5:2023", "API2:2023"
    severity: str            # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    endpoint: str
    method: str
    details: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    reproduction_curl: str
    remediation: str


class AuditSummary(BaseModel):
    total_endpoints_scanned: int
    total_tests_executed: int
    findings_count: Dict[str, int] = Field(default_factory=dict)
    findings: List[AuditFinding] = Field(default_factory=list)


class AuthorizationAuditor:
    """
    Executes differential access control tests across multiple security personas
    to identify BOLA, BFLA, and authentication bypasses.
    """

    def __init__(
        self,
        runner: SessionRunner,
        personas: Dict[str, Persona],
    ):
        self.runner = runner
        self.personas = personas
        self.findings: List[AuditFinding] = []
        self.tests_executed = 0

    async def audit_endpoint_unauthenticated(self, endpoint: APIEndpoint):
        """Checks if a protected endpoint can be accessed without authentication."""
        if not endpoint.requires_auth:
            return

        anon_persona = self.personas.get("anonymous") or Persona(name="anonymous", role="anonymous")

        # Use dummy or sample path parameters
        dummy_params = {p: "1" for p in endpoint.get_path_param_names()}

        result = await self.runner.execute_request(
            persona=anon_persona,
            endpoint_path=endpoint.path,
            method=endpoint.method,
            path_params=dummy_params,
        )
        self.tests_executed += 1

        # Protected endpoints must reject unauthenticated requests with 401 or 403
        if result.status_code in [200, 201, 204]:
            self.findings.append(
                AuditFinding(
                    title=f"Unauthenticated Access to Protected Endpoint ({endpoint.path})",
                    vulnerability_type="UNAUTHENTICATED_ACCESS",
                    owasp_id="API2:2023 - Broken Authentication",
                    severity="HIGH",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    details=(
                        f"The endpoint {endpoint.method} {endpoint.path} responded with HTTP "
                        f"{result.status_code} to an unauthenticated request. Authentication "
                        "middleware appears to be absent or misconfigured."
                    ),
                    evidence={
                        "status_code": result.status_code,
                        "response_snippet": result.response_body[:300],
                    },
                    reproduction_curl=result.curl_command,
                    remediation=(
                        "Enforce strict authentication middleware across all private routes. "
                        "Verify tokens/session cookies before dispatching to controller logic."
                    ),
                )
            )

    async def audit_endpoint_bfla(self, endpoint: APIEndpoint):
        """Checks if regular unprivileged users can invoke administrative endpoints."""
        if not endpoint.is_admin_candidate:
            return

        standard_user = self.personas.get("user_a")
        if not standard_user:
            return

        dummy_params = {p: "1" for p in endpoint.get_path_param_names()}

        result = await self.runner.execute_request(
            persona=standard_user,
            endpoint_path=endpoint.path,
            method=endpoint.method,
            path_params=dummy_params,
        )
        self.tests_executed += 1

        # If a non-admin gets 200/201/204, privilege check is missing
        if result.status_code in [200, 201, 204]:
            self.findings.append(
                AuditFinding(
                    title=f"Broken Function Level Authorization on Admin Endpoint ({endpoint.path})",
                    vulnerability_type="BFLA",
                    owasp_id="API5:2023 - Broken Function Level Authorization",
                    severity="CRITICAL" if endpoint.method in ["POST", "PUT", "DELETE"] else "HIGH",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    details=(
                        f"Standard user '{standard_user.name}' successfully invoked administrative "
                        f"endpoint {endpoint.method} {endpoint.path} receiving HTTP {result.status_code}. "
                        "Role-Based Access Control (RBAC) was not enforced."
                    ),
                    evidence={
                        "status_code": result.status_code,
                        "response_snippet": result.response_body[:300],
                    },
                    reproduction_curl=result.curl_command,
                    remediation=(
                        "Implement role-based authorization checks (e.g., verifying user.role == 'ADMIN') "
                        "at the route guard or middleware level before executing administrative operations."
                    ),
                )
            )

    async def audit_endpoint_bola(self, endpoint: APIEndpoint):
        """
        Tests for Broken Object Level Authorization (BOLA/IDOR).
        Attempts to access User A's owned resource using User B's credentials.
        """
        if not endpoint.has_path_params:
            return

        user_a = self.personas.get("user_a")
        user_b = self.personas.get("user_b")
        if not user_a or not user_b:
            return

        path_params = endpoint.get_path_param_names()

        # Check if we have defined owned resources for User A
        param_mapping_a: Dict[str, Any] = {}
        for param_name in path_params:
            if param_name in user_a.owned_resources:
                param_mapping_a[param_name] = user_a.owned_resources[param_name]
            elif "id" in param_name.lower() and "default_id" in user_a.owned_resources:
                param_mapping_a[param_name] = user_a.owned_resources["default_id"]
            else:
                param_mapping_a[param_name] = "1"

        # Step 1: Baseline Request (User A requests their own resource)
        baseline = await self.runner.execute_request(
            persona=user_a,
            endpoint_path=endpoint.path,
            method=endpoint.method,
            path_params=param_mapping_a,
        )
        self.tests_executed += 1

        # If baseline succeeds (200), proceed with cross-tenant check
        if baseline.status_code in [200, 201]:
            # Step 2: Cross-Tenant Substitution (User B requests User A's object)
            cross_swap = await self.runner.execute_request(
                persona=user_b,
                endpoint_path=endpoint.path,
                method=endpoint.method,
                path_params=param_mapping_a,
            )
            self.tests_executed += 1

            # BOLA Vulnerability Condition:
            # User B receives 200 OK for User A's private resource
            if cross_swap.status_code in [200, 201]:
                self.findings.append(
                    AuditFinding(
                        title=f"Broken Object Level Authorization (BOLA) in {endpoint.path}",
                        vulnerability_type="BOLA",
                        owasp_id="API1:2023 - Broken Object Level Authorization",
                        severity="CRITICAL",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        details=(
                            f"User '{user_b.name}' was able to access or modify resource "
                            f"{param_mapping_a} belonging to '{user_a.name}' via {endpoint.method} "
                            f"{endpoint.path}. Server returned HTTP {cross_swap.status_code}."
                        ),
                        evidence={
                            "owner_persona": user_a.name,
                            "attacker_persona": user_b.name,
                            "baseline_status": baseline.status_code,
                            "cross_swap_status": cross_swap.status_code,
                            "response_snippet": cross_swap.response_body[:300],
                        },
                        reproduction_curl=cross_swap.curl_command,
                        remediation=(
                            "Validate that the authenticated requester possesses explicit ownership "
                            "or tenancy over the requested object identifier in database queries. "
                            "Example: `SELECT * FROM items WHERE id = :id AND owner_id = :auth_user_id`."
                        ),
                    )
                )

    async def run_full_audit(self, endpoints: List[APIEndpoint]) -> AuditSummary:
        for ep in endpoints:
            await self.audit_endpoint_unauthenticated(ep)
            await self.audit_endpoint_bfla(ep)
            await self.audit_endpoint_bola(ep)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return AuditSummary(
            total_endpoints_scanned=len(endpoints),
            total_tests_executed=self.tests_executed,
            findings_count=severity_counts,
            findings=self.findings,
        )
