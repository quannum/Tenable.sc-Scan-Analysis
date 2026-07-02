import json
import unittest
from unittest.mock import patch

from src.tenable_coverage_workflow.subnet_source.github_connector import (
    load_github_yaml_repo,
)


class GitHubConnectorTests(unittest.TestCase):
    def test_recursively_loads_yaml_at_requested_ref_with_bearer_token(self):
        base = "https://ghe.example/api/v3"
        root_url = (
            f"{base}/repos/acme/networks/contents/sites?ref=release%2F2026"
        )
        directory_url = (
            f"{base}/repos/acme/networks/contents/sites/us?ref=release%2F2026"
        )
        file_url = (
            f"{base}/repos/acme/networks/contents/sites/us/nyc.yaml"
            "?ref=release%2F2026"
        )
        responses = {
            root_url: json.dumps(
                [
                    {
                        "type": "dir",
                        "path": "sites/us",
                        "url": f"{base}/repos/acme/networks/contents/sites/us",
                    }
                ]
            ).encode(),
            directory_url: json.dumps(
                [
                    {
                        "type": "file",
                        "path": "sites/us/nyc.yaml",
                        "url": (
                            f"{base}/repos/acme/networks/contents/"
                            "sites/us/nyc.yaml"
                        ),
                    }
                ]
            ).encode(),
            file_url: (
                b"site_code: NYC01\n"
                b"name: New York\n"
                b"region: US East\n"
                b"private_network_definition:\n"
                b"  network: 10.1.0.0\n"
                b"  cidr: 16\n"
            ),
        }
        calls = []

        def requester(url, headers, timeout):
            calls.append((url, headers, timeout))
            return responses[url]

        result = load_github_yaml_repo(
            api_url=base,
            repository="acme/networks",
            ref="release/2026",
            source_path="sites",
            token="token-value",
            timeout_seconds=12,
            requester=requester,
        )

        self.assertEqual(result.site_definitions[0].site_code, "NYC01")
        self.assertEqual(result.coverage_targets[0].cidr, "10.1.0.0/16")
        self.assertEqual([call[0] for call in calls], list(responses))
        self.assertTrue(
            all(call[1]["Authorization"] == "Bearer token-value" for call in calls)
        )
        self.assertEqual(calls[-1][1]["Accept"], "application/vnd.github.raw+json")
        self.assertTrue(all(call[2] == 12 for call in calls))

    def test_transient_request_is_retried(self):
        base = "https://ghe.example/api/v3"
        root_url = f"{base}/repos/acme/networks/contents?ref=main"
        file_url = f"{base}/repos/acme/networks/contents/site.yaml?ref=main"
        attempts = {root_url: 0}

        def requester(url, headers, timeout):
            if url == root_url:
                attempts[root_url] += 1
                if attempts[root_url] == 1:
                    raise TimeoutError("timed out")
                return json.dumps(
                    [
                        {
                            "type": "file",
                            "path": "site.yaml",
                            "url": file_url.split("?", 1)[0],
                        }
                    ]
                ).encode()
            return (
                b"site_code: LAB01\n"
                b"private_network_definition:\n"
                b"  network: 10.0.0.0\n"
                b"  cidr: 24\n"
            )

        with patch(
            "src.tenable_coverage_workflow.subnet_source.github_connector.time.sleep"
        ) as sleep:
            result = load_github_yaml_repo(
                base,
                "acme/networks",
                requester=requester,
            )

        self.assertEqual(result.site_definitions[0].site_code, "LAB01")
        self.assertEqual(attempts[root_url], 2)
        sleep.assert_called_once()

    def test_rejects_unsafe_repository_path(self):
        with self.assertRaisesRegex(ValueError, "Unsafe GitHub repository path"):
            load_github_yaml_repo(
                "https://ghe.example/api/v3",
                "acme/networks",
                source_path="../private",
                requester=lambda *_: b"[]",
            )


if __name__ == "__main__":
    unittest.main()
