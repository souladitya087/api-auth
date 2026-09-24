import asyncio
import sys
from pathlib import Path
import click
import yaml

from core.spec_parser import OpenAPISpecParser
from core.session_runner import Persona, SessionRunner
from core.auditor import AuthorizationAuditor
from core.reporter import AuditReporter


@click.group()
def cli():
    """AuthScope: Automated API Authorization & Access Control Auditor"""
    pass


@cli.command("inspect-spec")
@click.option("--spec", required=True, type=click.Path(exists=True), help="Path to OpenAPI spec file (JSON/YAML)")
def inspect_spec(spec):
    """Parses and lists endpoints categorized by access control test candidates."""
    parser = OpenAPISpecParser(spec)
    click.echo(f"\n[*] Loaded Spec: {spec}")
    click.echo(f"[*] Detected Base URL: {parser.base_url}")
    click.echo(f"[*] Total Auditable Endpoints Found: {len(parser.endpoints)}\n")

    click.echo(f"{'METHOD':<8} {'PATH':<35} {'PATH PARAMS':<15} {'BOLA CANDIDATE':<16} {'BFLA CANDIDATE'}")
    click.echo("-" * 95)
    for ep in parser.endpoints:
        path_params = ", ".join(ep.get_path_param_names()) or "None"
        bola_flag = "[YES]" if ep.has_path_params else "-"
        bfla_flag = "[YES]" if ep.is_admin_candidate else "-"
        click.echo(f"{ep.method:<8} {ep.path:<35} {path_params:<15} {bola_flag:<16} {bfla_flag}")
    click.echo("\n")


@cli.command("audit")
@click.option("--spec", required=True, type=click.Path(exists=True), help="Path to OpenAPI JSON/YAML")
@click.option("--config", required=True, type=click.Path(exists=True), help="Path to personas config YAML")
@click.option("--output-md", default="AUDIT_REPORT.md", help="Path to output Markdown report")
@click.option("--output-json", default="audit_report.json", help="Path to output JSON report")
def audit(spec, config, output_md, output_json):
    """Executes authorization differential audit against the target API."""
    with open(config, "r", encoding="utf-8") as f:
        conf_data = yaml.safe_load(f)

    target_url = conf_data.get("target_base_url", "http://127.0.0.1:8000")
    raw_personas = conf_data.get("personas", {})

    personas = {}
    for p_id, p_info in raw_personas.items():
        personas[p_id] = Persona(
            name=p_info.get("name", p_id),
            role=p_info.get("role", "user"),
            headers=p_info.get("headers", {}),
            cookies=p_info.get("cookies", {}),
            owned_resources=p_info.get("owned_resources", {}),
        )

    parser = OpenAPISpecParser(spec)
    runner = SessionRunner(base_url=target_url)
    auditor = AuthorizationAuditor(runner=runner, personas=personas)

    click.echo(f"\n[*] Starting AuthScope Audit...")
    click.echo(f"[*] Target URL : {target_url}")
    click.echo(f"[*] Personas   : {', '.join(personas.keys())}")
    click.echo(f"[*] Endpoints  : {len(parser.endpoints)}")
    click.echo("-" * 60)

    # Run asynchronous audit loop
    summary = asyncio.run(auditor.run_full_audit(parser.endpoints))

    reporter = AuditReporter(summary)
    terminal_output = reporter.generate_terminal_summary()
    click.echo(terminal_output)

    # Export reports
    reporter.export_markdown(output_md)
    reporter.export_json(output_json)
    click.echo(f"\n[+] Full Markdown Report saved to: {Path(output_md).resolve()}")
    click.echo(f"[+] Structured JSON Report saved to: {Path(output_json).resolve()}\n")


@cli.command("start-mock")
@click.option("--port", default=8000, help="Port to run mock server on")
def start_mock(port):
    """Runs the companion vulnerable multi-tenant mock API."""
    from mock_service.app import app
    click.echo(f"\n[*] Starting vulnerable-by-design mock API on http://127.0.0.1:{port}...")
    click.echo("[*] Use Ctrl+C to terminate the server.\n")
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    cli()
