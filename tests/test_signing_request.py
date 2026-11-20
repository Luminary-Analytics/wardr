"""The installer workflows trust only a signing request that names its own tag."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


SPEC = spec_from_file_location(
    "wardr_read_request", Path(__file__).resolve().parents[1] / "packaging/signing/read_request.py",
)
reader = module_from_spec(SPEC)
SPEC.loader.exec_module(reader)

REQUEST = {"schema_version": 1, "version": "0.3.4", "commit": "a" * 40, "wheel_sha256": "b" * 64}


class SigningRequestTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / reader.REQUEST.parent).mkdir(parents=True)

    def write(self, text):
        (self.root / reader.REQUEST).write_text(text, encoding="utf-8")

    def test_a_valid_request_on_its_tag(self):
        self.write(json.dumps(REQUEST))
        outputs = reader.read_request("refs/tags/sign-v0.3.4", self.root)
        self.assertEqual(outputs, {key: REQUEST[key] for key in ("version", "commit", "wheel_sha256")})

    def test_the_tag_must_name_the_requested_version(self):
        self.write(json.dumps(REQUEST))
        for ref in ("refs/tags/sign-v0.3.5", "refs/tags/v0.3.4", "refs/heads/main", "refs/tags/vwardrsign-0_3_4"):
            with self.assertRaisesRegex(ValueError, "signing tag"):
                reader.read_request(ref, self.root)

    def test_malformed_requests_are_refused(self):
        bad = [
            {**REQUEST, "extra": 1},
            {**REQUEST, "schema_version": True},
            {**REQUEST, "version": "0.3"},
            {**REQUEST, "commit": "A" * 40},
            {**REQUEST, "wheel_sha256": "b" * 63},
        ]
        for request in bad:
            self.write(json.dumps(request))
            with self.assertRaises(ValueError):
                reader.read_request("refs/tags/sign-v0.3.4", self.root)
        self.write('{"schema_version": 1, "schema_version": 1}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            reader.read_request("refs/tags/sign-v0.3.4", self.root)


if __name__ == "__main__":
    unittest.main()
