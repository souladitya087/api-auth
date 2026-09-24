import unittest
from core.spec_parser import OpenAPISpecParser
from core.session_runner import SessionRunner


class TestAuthScope(unittest.TestCase):
    def test_spec_parser_loads_endpoints(self):
        spec_path = "mock_service/openapi.json"
        parser = OpenAPISpecParser(spec_path)

        self.assertEqual(len(parser.endpoints), 4)
        paths = [ep.path for ep in parser.endpoints]
        self.assertIn("/api/v1/documents/{doc_id}", paths)
        self.assertIn("/api/v1/admin/system-stats", paths)
        self.assertIn("/api/v1/profile/{user_id}", paths)
        self.assertIn("/health", paths)

    def test_spec_parser_detects_bola_and_admin_candidates(self):
        parser = OpenAPISpecParser("mock_service/openapi.json")

        doc_ep = next(ep for ep in parser.endpoints if ep.path == "/api/v1/documents/{doc_id}")
        self.assertTrue(doc_ep.has_path_params)
        self.assertEqual(doc_ep.get_path_param_names(), ["doc_id"])

        admin_ep = next(ep for ep in parser.endpoints if ep.path == "/api/v1/admin/system-stats")
        self.assertTrue(admin_ep.is_admin_candidate)

    def test_curl_command_formatting(self):
        runner = SessionRunner(base_url="http://127.0.0.1:8000")
        curl = runner.format_curl(
            method="GET",
            url="http://127.0.0.1:8000/api/v1/documents/doc_101",
            headers={"Authorization": "Bearer token-bob-456"},
        )
        self.assertIn("curl", curl)
        self.assertIn("-X GET", curl)
        self.assertIn("token-bob-456", curl)


if __name__ == "__main__":
    unittest.main()
