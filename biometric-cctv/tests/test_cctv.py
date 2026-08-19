import json
import os
import tempfile
import unittest
from pathlib import Path

from cctv import (
    Allowlist,
    AllowlistError,
    AuthError,
    build_manifest,
    pull_frames,
    refuse_open_url,
)


def _write_allowlist(td: str, cameras: list[dict]) -> str:
    path = os.path.join(td, "allowlist.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "cameras": cameras}, f)
    return path


class TestAllowlist(unittest.TestCase):
    def test_unknown_camera_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_allowlist(
                td,
                [
                    {
                        "id": "lobby-1",
                        "rtsp_url": "mock://",
                        "holder": "alice",
                        "auth_kind": "owner_consent",
                    }
                ],
            )
            al = Allowlist.load(path)
            with self.assertRaises(AllowlistError):
                al.get("not-listed")

    def test_open_cam_host_banned(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_allowlist(
                td,
                [
                    {
                        "id": "bad",
                        "rtsp_url": "http://www.insecam.org/en/view/x/",
                        "holder": "alice",
                        "auth_kind": "owner_consent",
                    }
                ],
            )
            al = Allowlist.load(path)
            with self.assertRaises(AllowlistError):
                al.validate()

    def test_bad_auth_kind(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_allowlist(
                td,
                [
                    {
                        "id": "x",
                        "rtsp_url": "mock://",
                        "holder": "a",
                        "auth_kind": "open_internet",
                    }
                ],
            )
            with self.assertRaises(AllowlistError):
                Allowlist.load(path)

    def test_mock_pull_and_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_allowlist(
                td,
                [
                    {
                        "id": "lobby-1",
                        "rtsp_url": "mock://",
                        "holder": "alice",
                        "auth_kind": "client_consent",
                        "purposes": ["enrolment", "training"],
                    }
                ],
            )
            al = Allowlist.load(path)
            al.validate()
            out = os.path.join(td, "frames")
            result = pull_frames(al, "lobby-1", out, duration_s=6, every_s=2, mock=True)
            self.assertEqual(result.error, "")
            self.assertEqual(len(result.frames), 3)
            rows = build_manifest(out, client_id="alice", camera_id="lobby-1")
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0]["source_type"], "cctv_authorized")
            self.assertEqual(len(rows[0]["image_hash"]), 64)

    def test_dry_run(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_allowlist(
                td,
                [
                    {
                        "id": "lobby-1",
                        "rtsp_url": "rtsp://127.0.0.1/nope",
                        "holder": "alice",
                        "auth_kind": "owner_consent",
                    }
                ],
            )
            al = Allowlist.load(path)
            r = pull_frames(al, "lobby-1", td, dry_run=True)
            self.assertEqual(r.error, "dry_run")

    def test_refuse_open_url(self):
        with self.assertRaises(AuthError):
            refuse_open_url("http://insecam.example/1")


if __name__ == "__main__":
    unittest.main()
