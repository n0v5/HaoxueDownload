from __future__ import annotations

import getpass
import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
import os
import platform
from datetime import date, timedelta
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import requests
from cryptography.fernet import Fernet, InvalidToken
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/135 Safari/537.36"
PASSPORT = "https://passport.pku.edu.cn"
IAAA = "https://iaaa.pku.edu.cn/iaaa"
VERBOSE = False
AUTH_DIRECTORY_NAME = "HaoxueDownload"
COOKIE_FILENAME = "cookies.enc"
KEY_FILENAME = "cookies.key"

PLAYBACK_STATUS_LABELS = {
    "1": "live",
    "2": "not started",
    "3": "replay generating",
    "4": "no access",
    "5": "replay unavailable",
    "6": "replay available",
}


def debug(*args, **kwargs) -> None:
    if VERBOSE:
        print(*args, **kwargs)


class HiddenInputs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        data = dict(attrs)
        name = data.get("name")
        if name:
            self.values[name] = data.get("value") or ""


def response_shape(body: str) -> str:
    try:
        value = json.loads(body)
    except Exception:
        return "non-JSON"
    if isinstance(value, dict):
        return "{" + ", ".join(sorted(value)) + "}"
    if isinstance(value, list):
        return f"[{len(value)} items]"
    return type(value).__name__


def show_response(response: requests.Response, body: str = "") -> None:
    debug(f"HTTP {response.status_code} {response.reason}")
    if response.headers.get("Location"):
        debug("Location:", response.headers["Location"])
    cookie_names = []
    for header in response.raw.headers.get_all("Set-Cookie") or []:
        cookie_names.append(header.split("=", 1)[0])
    if cookie_names:
        debug("Set-Cookie names:", ", ".join(sorted(set(cookie_names))))
    if body:
        debug("Response shape:", response_shape(body))
        try:
            value = json.loads(body)
            if isinstance(value, dict) and "success" in value:
                debug("success:", value["success"])
            for field in ("err", "errMsg", "message", "code"):
                if isinstance(value, dict) and field in value:
                    debug(f"{field}:", str(value[field])[:300])
            if isinstance(value, dict) and "errors" in value:
                debug("errors shape:", response_shape(json.dumps(value["errors"])))
        except Exception:
            compact = re.sub(r"\s+", " ", body).strip()
            compact = re.sub(
                r"(?i)(password|token|userName|cookie|access_token)\s*[=:]\s*[\"']?[^&\s\"']+",
                r"\1=<redacted>",
                compact,
            )
            debug("Body preview:", compact[:240])


def show_callback_clues(body: str) -> None:
    debug("Callback script/src clues:")
    found = 0
    for line in body.splitlines():
        if re.search(r"(?i)(script|bridge|PKULoginSuccess|userInfo|userinfo|_token|token|redirect|json)", line):
            compact = re.sub(r"\s+", " ", line).strip()
            compact = re.sub(
                r"(?i)(password|token|userName|cookie|access_token|_token2?)\s*[=:]\s*[\"']?[^&\s\"'<>]+",
                r"\1=<redacted>",
                compact,
            )
            debug(" ", compact[:500])
            found += 1
            if found >= 40:
                debug("  ... output capped at 40 lines")
                break
    if found == 0:
        debug("  none found in inline HTML")
    visible = re.sub(r"<script.*?</script>|<style.*?</style>", " ", body, flags=re.I | re.S)
    visible = re.sub(r"<[^>]+>", " ", visible)
    visible = re.sub(r"\s+", " ", visible).strip()
    if visible:
        debug("Callback visible text:", visible[:300])


def request(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("headers", {})
    kwargs["headers"].setdefault("User-Agent", UA)
    return session.request(method, url, timeout=30, allow_redirects=False, **kwargs)


def _absolute_env_path(name: str) -> Path | None:
    """Read a platform directory variable only when it is a valid absolute path."""
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    candidate = Path(value).expanduser()
    return candidate if candidate.is_absolute() else None


def auth_directory() -> Path:
    """Return the platform-standard per-user data directory.

    The location is deliberately independent of the repository and current
    working directory. Environment variables are accepted only when absolute,
    as required by the relevant platform conventions.
    """
    home = Path.home()
    system = platform.system()
    if system == "Windows":
        root = _absolute_env_path("LOCALAPPDATA") or (home / "AppData" / "Local")
    elif system == "Darwin":
        root = home / "Library" / "Application Support"
    else:
        root = _absolute_env_path("XDG_DATA_HOME") or (home / ".local" / "share")
    return (root / AUTH_DIRECTORY_NAME).resolve()


def restrict_file(path: Path) -> None:
    """Restrict files/directories on POSIX; Windows uses the profile ACL."""
    if os.name != "nt":
        path.chmod(0o600)


def prepare_auth_directory() -> Path:
    directory = auth_directory()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        directory.chmod(0o700)
    if not directory.is_dir():
        raise OSError(f"authentication path is not a directory: {directory}")
    return directory


def auth_paths() -> tuple[Path, Path]:
    directory = auth_directory()
    return directory / COOKIE_FILENAME, directory / KEY_FILENAME


def save_login_cookies(session: requests.Session) -> bool:
    """Store encrypted session cookies in the per-user data directory."""
    try:
        cookies = [
            {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "expires": cookie.expires,
                "secure": cookie.secure,
            }
            for cookie in session.cookies
        ]
        cookie_path, key_path = auth_paths()
        prepare_auth_directory()
        if not key_path.exists():
            key_path.write_bytes(Fernet.generate_key())
            restrict_file(key_path)
        key = key_path.read_bytes()
        encrypted = Fernet(key).encrypt(json.dumps(cookies, separators=(",", ":")).encode())
        temporary = cookie_path.with_name(cookie_path.name + ".tmp")
        temporary.write_bytes(encrypted)
        restrict_file(temporary)
        temporary.replace(cookie_path)
        restrict_file(cookie_path)
        return True
    except Exception as exc:
        debug("Could not save encrypted login state:", type(exc).__name__, str(exc)[:160])
        return False


def load_login_cookies(session: requests.Session) -> bool:
    """Restore encrypted session cookies from the per-user data directory."""
    try:
        cookie_path, key_path = auth_paths()
        if not cookie_path.is_file() or not key_path.is_file():
            return False
        records = json.loads(Fernet(key_path.read_bytes()).decrypt(cookie_path.read_bytes()).decode())
        if not isinstance(records, list):
            return False
        for record in records:
            if not isinstance(record, dict) or not record.get("name"):
                continue
            cookie_kwargs = {
                "path": str(record.get("path", "/")),
                "expires": record.get("expires"),
                "secure": bool(record.get("secure", False)),
            }
            if record.get("domain"):
                cookie_kwargs["domain"] = str(record["domain"])
            session.cookies.set(
                str(record["name"]), str(record.get("value", "")), **cookie_kwargs
            )
        return bool(session.cookies)
    except (InvalidToken, OSError, ValueError, TypeError) as exc:
        debug("Could not load encrypted login state:", type(exc).__name__)
        return False


def saved_login_is_valid(session: requests.Session) -> bool:
    """Validate a restored cookie jar against the authenticated course API."""
    api_token = next((c.value for c in session.cookies if c.name == "_token2"), "")
    if not api_token:
        return False
    response = course_api(session, "v3/course/get-use-member", {"page": "1"}, api_token)
    if not response.ok:
        return False
    try:
        value = response.json()
    except ValueError:
        return False
    return isinstance(value, dict) and value.get("success") is not False


def api_sign(params: dict[str, str]) -> str:
    material = "".join(key + params[key] for key in sorted(params))
    return hashlib.md5((material + "8225ca5fa4d56d6fde540db6024fba39").encode()).hexdigest()


def course_api(session: requests.Session, path: str, params: dict[str, str], api_token: str) -> requests.Response:
    signed = {key: value for key, value in params.items() if value != ""}
    signed.update({
        "tenantid": "d438cafb4c34b3b49b3a523bbef50203",
        "tenantId": "d438cafb4c34b3b49b3a523bbef50203",
        "api_version": "3.12.0",
        "app_id": "50",
        "client": "android",
    })
    signed["sign"] = api_sign(signed)
    return request(
        session,
        "GET",
        "https://yjapise.pku.edu.cn/courseapi/" + path,
        params=signed,
        headers={"token": api_token, "urlname": "courseapi"},
    )


def json_data(response: requests.Response):
    try:
        value = response.json()
    except ValueError:
        return None
    if isinstance(value, dict) and value.get("success") is False:
        debug("API error:", value.get("err"), str(value.get("errMsg", ""))[:200])
    return value.get("data") if isinstance(value, dict) else value


def print_course_records(data) -> None:
    records = data.get("lists", []) if isinstance(data, dict) else []
    print(f"Course records: {len(records)}")
    for index, item in enumerate(records, 1):
        if not isinstance(item, dict):
            continue
        print(
            f"  [{index}] course_id={item.get('course_id')}, "
            f"course_name={item.get('course_name')}, "
            f"teacher={item.get('course_teacher')}, "
            f"college={item.get('course_college')}, "
            f"term={item.get('course_term')}"
        )


def print_date_records(
    records: list[dict], hidden_course_ids: set[str] | None = None,
) -> None:
    hidden_course_ids = hidden_course_ids or set()
    print(f"Date records: {len(records)}")
    for index, item in enumerate(records, 1):
        status = str(item.get("sub_status", ""))
        course_id = str(item.get("course_id", ""))
        hidden_tag = " [hidden-course]" if course_id in hidden_course_ids else ""
        print(
            f"  [{index}] course={item.get('course_name')} (id={course_id}), "
            f"lesson={item.get('sub_name')}, teacher={item.get('course_teacher')}, "
            f"room={item.get('room_name')}, start={item.get('start_at')}, "
            f"end={item.get('end_at')}, status={status} "
            f"({PLAYBACK_STATUS_LABELS.get(status, 'unknown')}){hidden_tag}"
        )
    if hidden_course_ids:
        hidden_records = sum(
            1 for item in records if str(item.get("course_id", "")) in hidden_course_ids
        )
        print(
            f"Hidden courses: {len(hidden_course_ids)} course(s), "
            f"{hidden_records} record(s) not returned by course search."
        )


def resolve_record_choice(records: list, choice: str, id_key: str) -> str:
    """Resolve an already-read 1-based index or a record's existing ID."""
    if not isinstance(records, list):
        print(f"No selectable records for {id_key}.")
        return ""
    choice = choice.strip()
    if not choice:
        return ""
    # Prefer an exact ID match so numeric IDs are not mistaken for list indexes.
    for item in records:
        if isinstance(item, dict) and str(item.get(id_key, "")).strip() == choice:
            return choice
    try:
        index = int(choice)
    except ValueError:
        index = 0
    if 1 <= index <= len(records) and isinstance(records[index - 1], dict):
        value = records[index - 1].get(id_key)
        if value is not None and str(value).strip():
            return str(value).strip()
    print(f"No matching {id_key}: {choice}")
    return ""


def select_record_value(records: list, prompt: str, id_key: str) -> str:
    """Accept either the displayed 1-based index or the record's existing ID."""
    if not isinstance(records, list):
        print(f"No selectable records for {id_key}.")
        return ""
    return resolve_record_choice(records, input(prompt), id_key)


def print_sub_records(data, hidden_subjects: list | None = None) -> None:
    # get-course-detail maps to PlaybackVideoListBean.Data, whose subject
    # collection is named sub_list (the course-list endpoint uses lists).
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]
    records = data.get("sub_list", []) if isinstance(data, dict) else []
    all_records = list(records) + (hidden_subjects or [])
    hidden_count = len(hidden_subjects) if hidden_subjects else 0
    print(f"Subject records: {len(records)} (+{hidden_count} hidden)")
    for index, item in enumerate(all_records, 1):
        if not isinstance(item, dict):
            continue
        hidden_tag = " [hidden]" if item.get("_hidden") else ""
        vid_tag = f" videos={item.get('_video_count', 0)}" if item.get("_video_count") else ""
        print(
            f"  [{index}] sub_id={item.get('id')}, title={item.get('sub_title')}, "
            f"status={item.get('sub_status')}, begin={item.get('class_begin')}, "
            f"over={item.get('class_over')}, playback_status={item.get('playback_status')}"
            f"{vid_tag}{hidden_tag}"
        )
    if not records and isinstance(data, dict):
        print("Subject response keys:", ", ".join(sorted(data)))


def classify_media_url(url: str) -> str:
    suffix = Path(urlsplit(url).path).suffix.lower()
    if suffix == ".m3u8":
        return "hls"
    if suffix in {".mp4", ".m4v", ".mov", ".mkv", ".flv", ".webm", ".ts"}:
        return "file"
    return "unknown"


def _http_url(value) -> str:
    text = unescape(str(value or "")).strip()
    return text if text.startswith(("http://", "https://")) else ""


def extract_media_candidates(data) -> list[dict]:
    """Collect every media URL the sub-detail response exposes.

    Processed replays are usually HLS, while freshly published ones can be a
    plain MP4 served from httpDownload.  Keep the API's order and de-duplicate
    by host/path so an expiring query string cannot create duplicates.
    """
    if not isinstance(data, dict):
        debug("Video info data shape:", response_shape(json.dumps(data)))
        return []
    video_data = data.get("data", data)
    if not isinstance(video_data, dict):
        debug("Video info data shape:", response_shape(json.dumps(video_data)))
        return []
    debug("Video info keys:", ", ".join(sorted(video_data)))
    raw: list[tuple[str, str, int]] = []
    choices = video_data.get("videoArr") or []
    debug(f"Video choices: {len(choices) if isinstance(choices, list) else 0}")
    if isinstance(choices, list):
        for item in choices:
            if not isinstance(item, dict):
                continue
            url = _http_url(item.get("path"))
            if not url:
                continue
            try:
                size = int(item.get("file_size") or 0)
            except (TypeError, ValueError):
                size = 0
            parsed = urlsplit(url)
            debug(
                f"  tag={item.get('tag')}, size={size}, host={parsed.netloc}, "
                f"path={parsed.path}, query_keys="
                f"{','.join(sorted({part.split('=', 1)[0] for part in parsed.query.split('&') if part}))}"
            )
            raw.append((url, str(item.get("tag") or "video"), size))
    sub_content = video_data.get("sub_content") or {}
    if isinstance(sub_content, dict):
        saved = sub_content.get("save_playback") or {}
        if isinstance(saved, dict):
            raw.append((_http_url(saved.get("contents")), "saved playback", 0))
        playback = sub_content.get("playback") or {}
        if isinstance(playback, dict):
            raw.append((_http_url(playback.get("url")), "playback", 0))
        files = sub_content.get("file_list") or []
        if isinstance(files, list):
            for item in files:
                if not isinstance(item, dict):
                    continue
                url = _http_url(item.get("file_name"))
                if url and classify_media_url(url) == "file":
                    raw.append((url, str(item.get("file_type") or "file"), 0))
        firm = sub_content.get("firm_source") or {}
        if isinstance(firm, dict):
            raw.append((_http_url(firm.get("contents")), "cloud source", 0))

    candidates: list[dict] = []
    seen: set[str] = set()
    for url, label, size in raw:
        if not url:
            continue
        absolute = urlsplit(url)
        identity = urlunsplit((absolute.scheme, absolute.netloc, absolute.path, "", ""))
        if identity in seen:
            continue
        seen.add(identity)
        candidates.append({
            "url": url,
            "label": label,
            "size": size,
            "kind": classify_media_url(url),
        })
    return candidates


def _time_slot_key(title: str) -> str:
    m = re.search(r"第\d+-\d+节", title or "")
    return m.group(0) if m else ""


def _detect_global_step(visible_subjects: list[dict]) -> int:
    groups: dict[str, list[int]] = {}
    for s in visible_subjects:
        if not isinstance(s, dict):
            continue
        try:
            sid = int(s.get("id", 0))
        except (TypeError, ValueError):
            continue
        if sid <= 0:
            continue
        key = _time_slot_key(s.get("sub_title", "") or s.get("title", ""))
        if key:
            groups.setdefault(key, []).append(sid)
    for ids in groups.values():
        if len(ids) >= 2:
            ids_sorted = sorted(ids)
            diffs = [b - a for a, b in zip(ids_sorted, ids_sorted[1:]) if b > a]
            if diffs:
                diffs.sort()
                return diffs[len(diffs) // 2]
    return 4


def scan_hidden_subjects(
    session: requests.Session, course_id: str, visible_subjects: list[dict], api_token: str,
) -> list[dict]:
    """Find subjects hidden by playback_status filtering via sub_id enumeration."""
    step = _detect_global_step(visible_subjects)
    groups: dict[str, list[int]] = {}
    visible_ids: set[int] = set()
    for s in visible_subjects:
        if not isinstance(s, dict):
            continue
        try:
            sid = int(s.get("id", 0))
        except (TypeError, ValueError):
            continue
        if sid <= 0:
            continue
        visible_ids.add(sid)
        key = _time_slot_key(s.get("sub_title", "") or s.get("title", ""))
        groups.setdefault(key or "_unknown", []).append(sid)
    if not groups:
        return []

    scan_starts = []
    for slot, ids in groups.items():
        ids.sort()
        scan_starts.append((slot, ids[0]))
    scan_starts.sort(key=lambda t: t[1])

    debug(f"Hidden scan: global_step={step} scan_starts={scan_starts}")
    hidden: list[dict] = []
    seen: set[int] = set(visible_ids)

    for slot, group_min in scan_starts:
        misses = 0
        for probe_id in range(group_min - step, max(group_min - 200, 0), -step):
            if probe_id <= 0 or probe_id in seen:
                continue
            try:
                r = course_api(
                    session, "v3/course/get-course-sub-detail",
                    {"course_id": course_id, "sub_id": str(probe_id)}, api_token,
                )
                d = r.json()
                if not d.get("success"):
                    misses += 1
                    if misses >= 5:
                        break
                    continue
                vd = d.get("data", d) if isinstance(d, dict) else d
                if not isinstance(vd, dict):
                    misses += 1
                    continue
                if str(vd.get("course_id", "")) != str(course_id):
                    misses += 1
                    continue
                misses = 0
                seen.add(probe_id)
                va = vd.get("videoArr", [])
                if not isinstance(va, list):
                    va = []
                pb = 0
                sc = vd.get("sub_content")
                if isinstance(sc, dict):
                    pb = sc.get("playback_status", 0) or 0
                hidden.append({
                    "id": str(probe_id),
                    "p_id": "0",
                    "sub_title": vd.get("title", ""),
                    "type": "course_live",
                    "class_begin": "",
                    "class_over": "",
                    "sub_status": "6" if len(va) > 0 else "2",
                    "click_record_num": "0",
                    "lecturer": "",
                    "lecturer_name": "",
                    "is_open": "",
                    "is_share": "",
                    "is_export": "",
                    "show": "yes",
                    "is_public": "",
                    "sub_delete": "0",
                    "sub_review_type": "",
                    "sub_data_id": "",
                    "playback_status": str(pb),
                    "olive_type": "",
                    "precondition_time": "",
                    "finished": 0,
                    "_hidden": True,
                    "_video_count": len(va),
                })
                debug(f"  Hidden: sub_id={probe_id} title={vd.get('title')} videos={len(va)}")
            except Exception as e:
                debug(f"  Probe error for {probe_id}:", e)
                misses += 1
            time.sleep(0.15)

    hidden.sort(key=lambda s: int(s.get("id", 0)))
    return hidden


def safe_filename(value: str) -> str:
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).strip(" .")
    return value or "replay"


def playlist_duration(body: str) -> float:
    return sum(float(match) for match in re.findall(r"#EXTINF:([0-9]+(?:\.[0-9]+)?)", body))


def format_time(seconds: float) -> str:
    seconds = max(0, int(seconds))
    return f"{seconds // 3600:02}:{seconds % 3600 // 60:02}:{seconds % 60:02}"


def describe_exception(exc: Exception) -> str:
    """Describe an error without echoing URLs that may carry access tokens."""
    status = getattr(getattr(exc, "response", None), "status_code", "")
    return f"{type(exc).__name__}{f' HTTP {status}' if status else ''}"


def format_bytes(value: float) -> str:
    value = max(0.0, float(value))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def run_ffmpeg_with_progress(command: list[str], duration: float) -> int:
    command = [*command[: command.index("-i")], "-progress", "pipe:1", "-nostats", *command[command.index("-i"):]]
    stderr = None if VERBOSE else subprocess.DEVNULL
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1)
    current = 0.0
    started_at = time.monotonic()
    if process.stdout:
        for line in process.stdout:
            key, _, value = line.strip().partition("=")
            if key == "out_time_ms":
                current = int(value or 0) / 1_000_000
                elapsed = time.monotonic() - started_at
                if duration > 0:
                    ratio = min(current / duration, 1.0)
                    width = 32
                    bar = "#" * int(width * ratio) + "-" * (width - int(width * ratio))
                    eta = elapsed * (duration / current - 1) if current > 0 else 0
                    print(
                        f"\rffmpeg [{bar}] {ratio * 100:5.1f}% "
                        f"processed {format_time(current)}/{format_time(duration)} "
                        f"elapsed {format_time(elapsed)} ETA {format_time(eta)}",
                        end="", flush=True,
                    )
                else:
                    print(
                        f"\rffmpeg processed {format_time(current)} "
                        f"elapsed {format_time(elapsed)}",
                        end="", flush=True,
                    )
    code = process.wait()
    print()
    return code


def playlist_identity(body: str, playlist_url: str) -> str:
    """Return an identity that survives changes to expiring URL query strings."""
    normalized: list[str] = []
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            line = re.sub(
                r'URI="([^"]+)"',
                lambda match: 'URI="' + urlunsplit(
                    (*urlsplit(urljoin(playlist_url, match.group(1)))[:3], "", "")
                ) + '"',
                line,
            )
            normalized.append(line)
            continue
        absolute = urlsplit(urljoin(playlist_url, line))
        normalized.append(urlunsplit((absolute.scheme, absolute.netloc, absolute.path, "", "")))
    return hashlib.sha256("\n".join(normalized).encode()).hexdigest()


def fetch_media_playlist(
    session: requests.Session, playlist_url: str, headers: dict[str, str], depth: int = 0,
) -> tuple[str, str]:
    """Resolve a master playlist to its highest-bandwidth media playlist."""
    if depth > 5:
        raise RuntimeError("HLS playlist nesting is too deep")
    response = session.get(
        playlist_url, headers={"User-Agent": UA, **headers}, timeout=30,
        allow_redirects=True, stream=True,
    )
    try:
        response.raise_for_status()
        content = bytearray()
        for chunk in response.iter_content(chunk_size=256 * 1024):
            if chunk:
                content.extend(chunk)
                if len(content) > 16 * 1024 * 1024:
                    raise RuntimeError("HLS playlist exceeds 16 MiB; refusing unsafe response")
        body = bytes(content).decode(response.encoding or "utf-8", errors="replace")
    finally:
        response.close()
    if "#EXTM3U" not in body[:4096]:
        raise RuntimeError("media URL did not return an HLS playlist")
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    variants: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if not line.startswith("#EXT-X-STREAM-INF:"):
            continue
        match = re.search(r"(?:^|,)BANDWIDTH=(\d+)", line)
        bandwidth = int(match.group(1)) if match else 0
        if index + 1 < len(lines) and not lines[index + 1].startswith("#"):
            variants.append((bandwidth, urljoin(response.url, lines[index + 1])))
    if variants:
        _, selected_url = max(variants, key=lambda item: item[0])
        debug(f"Selected HLS variant from {len(variants)} choices")
        return fetch_media_playlist(session, selected_url, headers, depth + 1)
    return response.url, body


def download_cached_resource(
    session: requests.Session, url: str, destination: Path, headers: dict[str, str],
) -> bool:
    """Download one resource atomically. Return False when it was cached."""
    if destination.is_file() and destination.stat().st_size > 0:
        return False
    temporary = destination.with_name(destination.name + ".part")
    try:
        with session.get(
            url, headers={"User-Agent": UA, **headers}, timeout=30,
            allow_redirects=True, stream=True,
        ) as response:
            response.raise_for_status()
            expected = int(response.headers.get("Content-Length", "0") or 0)
            written = 0
            with temporary.open("wb") as output:
                for chunk in response.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        output.write(chunk)
                        written += len(chunk)
        if written == 0 or (expected and written != expected):
            raise IOError(f"incomplete response: expected {expected}, received {written}")
        temporary.replace(destination)
        return True
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def cache_hls_playlist(
    session: requests.Session, playlist_url: str, body: str, cache_dir: Path,
    headers: dict[str, str],
) -> tuple[Path, int, int]:
    """Cache HLS resources and write a playlist that refers only to local files."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    identity_file = cache_dir / "playlist.sha256"
    identity = playlist_identity(body, playlist_url)
    if identity_file.exists() and identity_file.read_text(encoding="ascii").strip() != identity:
        raise RuntimeError(
            f"playlist differs from the cache in {cache_dir}; choose another output "
            "name or remove that cache directory"
        )

    identity_file.write_text(identity + "\n", encoding="ascii")

    lines = body.splitlines()
    segment_urls = []
    segment_durations = []
    pending_duration = 0.0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#EXTINF:"):
            match = re.match(r"#EXTINF:([0-9]+(?:\.[0-9]+)?)", stripped)
            pending_duration = float(match.group(1)) if match else 0.0
        elif stripped and not stripped.startswith("#"):
            segment_urls.append(urljoin(playlist_url, stripped))
            segment_durations.append(pending_duration)
            pending_duration = 0.0
    total = len(segment_urls)
    if not total:
        raise RuntimeError("media playlist contains no segments")

    local_lines: list[str] = []
    downloaded = 0
    ready_duration = 0.0
    total_duration = sum(segment_durations)
    started_at = time.monotonic()
    segment_index = 0
    auxiliary_names: dict[str, str] = {}
    segment_names: dict[str, str] = {}

    def cache_auxiliary(remote_url: str, kind: str) -> str:
        nonlocal downloaded
        absolute_url = urljoin(playlist_url, remote_url)
        if absolute_url not in auxiliary_names:
            suffix = Path(urlsplit(absolute_url).path).suffix or ".bin"
            name = f"{kind}_{len(auxiliary_names) + 1:03d}{suffix}"
            if download_cached_resource(session, absolute_url, cache_dir / name, headers):
                downloaded += 1
            auxiliary_names[absolute_url] = name
        return auxiliary_names[absolute_url]

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#EXT-X-KEY:") and 'URI="' in line:
            line = re.sub(
                r'URI="([^"]+)"',
                lambda match: f'URI="{cache_auxiliary(match.group(1), "key")}"',
                line,
            )
        elif line.startswith("#EXT-X-MAP:") and 'URI="' in line:
            line = re.sub(
                r'URI="([^"]+)"',
                lambda match: f'URI="{cache_auxiliary(match.group(1), "init")}"',
                line,
            )
        elif not line.startswith("#"):
            segment_index += 1
            remote_url = urljoin(playlist_url, line)
            local_name = segment_names.get(remote_url)
            was_downloaded = False
            if local_name is None:
                suffix = Path(urlsplit(remote_url).path).suffix or ".ts"
                local_name = f"segment_{segment_index:06d}{suffix}"
                segment_names[remote_url] = local_name
                was_downloaded = download_cached_resource(
                    session, remote_url, cache_dir / local_name, headers,
                )
            if was_downloaded:
                downloaded += 1
            ready_duration += segment_durations[segment_index - 1]
            state = "downloaded" if was_downloaded else "cached"
            elapsed = time.monotonic() - started_at
            eta = (
                elapsed * (total_duration / ready_duration - 1)
                if ready_duration > 0 else 0
            )
            print(
                f"\rSegments: {segment_index}/{total} ({state}) "
                f"ready {format_time(ready_duration)}/{format_time(total_duration)} "
                f"elapsed {format_time(elapsed)} ETA {format_time(eta)}",
                end="", flush=True,
            )
            line = local_name
        local_lines.append(line)
    print()

    local_playlist = cache_dir / "local.m3u8"
    local_playlist.write_text("\n".join(local_lines) + "\n", encoding="utf-8")
    return local_playlist, downloaded, total


def resumable_hls_download(
    session: requests.Session, media_url: str, media_cookie: str,
    output_path: Path, ffmpeg: str,
    playlist: tuple[str, str] | None = None,
) -> None:
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cache_dir = output_path.parent / f"{output_path.name}.segments"
    headers = {"Cookie": f"_token={media_cookie}"}
    if playlist is None:
        playlist_url, body = fetch_media_playlist(session, media_url, headers)
    else:
        playlist_url, body = playlist
    duration = playlist_duration(body)
    local_playlist, downloaded, total = cache_hls_playlist(
        session, playlist_url, body, cache_dir, headers,
    )
    print(f"Segments ready: {total}; downloaded now: {downloaded}; cache: {cache_dir}")

    temporary_output = output_path.with_name(
        output_path.stem + ".part" + (output_path.suffix or ".mp4")
    )
    command = [
        ffmpeg, "-hide_banner", "-y", "-protocol_whitelist", "file,crypto,data",
        "-allowed_extensions", "ALL",
        "-i", str(local_playlist), "-c", "copy", str(temporary_output),
    ]
    print("Joining cached segments with ffmpeg.")
    result_code = run_ffmpeg_with_progress(command, duration)
    print("ffmpeg exit code:", result_code)
    if result_code != 0:
        temporary_output.unlink(missing_ok=True)
        print("Join failed; cached segments were kept for the next run.")
        return
    temporary_output.replace(output_path)
    shutil.rmtree(cache_dir)
    print("Saved:", output_path)
    print("Segment cache removed.")


def resumable_file_download(
    session: requests.Session, media_url: str, media_cookie: str,
    output_path: Path, expected_size: int = 0,
) -> None:
    """Download a plain media file with HTTP Range resume support."""
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(
        output_path.stem + ".part" + (output_path.suffix or ".mp4")
    )
    offset = temporary.stat().st_size if temporary.is_file() else 0
    headers = {"User-Agent": UA, "Cookie": f"_token={media_cookie}"}
    if offset:
        headers["Range"] = f"bytes={offset}-"

    with session.get(
        media_url, headers=headers, timeout=60, allow_redirects=True, stream=True,
    ) as response:
        if response.status_code == 416 and offset:
            match = re.search(r"/(\d+)\s*$", response.headers.get("Content-Range", ""))
            total = int(match.group(1)) if match else expected_size
            if total and offset >= total:
                temporary.replace(output_path)
                print("Already complete; saved:", output_path)
                return
        response.raise_for_status()
        if response.status_code == 206:
            match = re.search(r"/(\d+)\s*$", response.headers.get("Content-Range", ""))
            if match:
                total = int(match.group(1))
            else:
                length = int(response.headers.get("Content-Length", "0") or 0)
                total = offset + length if length else 0
            mode = "ab"
        else:
            if offset:
                print("Server ignored the resume request; restarting from zero.")
                offset = 0
            total = int(response.headers.get("Content-Length", "0") or 0) or expected_size
            mode = "wb"
        total = total or expected_size
        print(
            f"Starting direct download"
            f"{f' (resuming at {format_bytes(offset)})' if offset else ''}; "
            "URL and cookie are hidden."
        )
        written = offset
        started_at = time.monotonic()
        with temporary.open(mode) as output:
            for chunk in response.iter_content(chunk_size=1024 * 256):
                if not chunk:
                    continue
                output.write(chunk)
                written += len(chunk)
                elapsed = max(time.monotonic() - started_at, 1e-6)
                if total > 0:
                    ratio = min(written / total, 1.0)
                    width = 32
                    bar = "#" * int(width * ratio) + "-" * (width - int(width * ratio))
                    speed = (written - offset) / elapsed
                    eta = (total - written) / speed if speed > 0 else 0
                    print(
                        f"\rDownload [{bar}] {ratio * 100:5.1f}% "
                        f"{format_bytes(written)}/{format_bytes(total)} "
                        f"elapsed {format_time(elapsed)} ETA {format_time(eta)}",
                        end="", flush=True,
                    )
                else:
                    print(
                        f"\rDownload {format_bytes(written)} "
                        f"elapsed {format_time(elapsed)}",
                        end="", flush=True,
                    )
    print()
    final_size = temporary.stat().st_size
    if total and final_size != total:
        raise IOError(f"incomplete download: expected {total} bytes, received {final_size}")
    temporary.replace(output_path)
    print("Saved:", output_path)


def read_media_prefix(
    session: requests.Session, url: str, headers: dict[str, str], limit: int = 64 * 1024,
) -> tuple[str, bytes, int, str]:
    """Read a small response prefix without pulling a whole media file."""
    response = session.get(
        url, headers={"User-Agent": UA, **headers}, timeout=30,
        allow_redirects=True, stream=True,
    )
    try:
        response.raise_for_status()
        prefix = bytearray()
        for chunk in response.iter_content(chunk_size=8 * 1024):
            if chunk:
                prefix.extend(chunk)
                if len(prefix) >= limit:
                    break
        raw_length = response.headers.get("Content-Length", "")
        length = int(raw_length) if raw_length.isdigit() else 0
        return response.url, bytes(prefix), length, response.headers.get("Content-Type", "")
    finally:
        response.close()


def probe_media(
    session: requests.Session, candidate: dict, headers: dict[str, str],
) -> dict | None:
    """Return download details for one candidate URL, or None when unusable."""
    url = candidate["url"]
    if candidate["kind"] == "hls":
        try:
            playlist_url, body = fetch_media_playlist(session, url, headers)
        except Exception as exc:
            debug(f"HLS probe failed ({describe_exception(exc)})")
            return None
        return {
            **candidate,
            "kind": "hls",
            "playlist_url": playlist_url,
            "body": body,
            "duration": playlist_duration(body),
        }
    try:
        _, prefix, length, content_type = read_media_prefix(session, url, headers)
    except Exception as exc:
        debug(f"Media probe failed ({describe_exception(exc)})")
        return None
    if not prefix:
        debug("Media probe returned an empty response")
        return None
    if b"#EXTM3U" in prefix[:4096]:
        try:
            playlist_url, body = fetch_media_playlist(session, url, headers)
        except Exception as exc:
            debug(f"HLS probe failed ({describe_exception(exc)})")
            return None
        return {
            **candidate,
            "kind": "hls",
            "playlist_url": playlist_url,
            "body": body,
            "duration": playlist_duration(body),
        }
    return {
        **candidate,
        "kind": "file",
        "content_type": content_type or "unknown type",
        "size": candidate["size"] or length,
    }


def fetch_all_courses(session: requests.Session, search: str, api_token: str) -> list[dict]:
    """Fetch all pages, using the app's full-page load-more fallback."""
    records: list[dict] = []
    seen_ids: set[str] = set()
    page = 1
    while True:
        response = course_api(
            session,
            "v3/course/get-use-member",
            {"page": str(page), "search": search},
            api_token,
        )
        data = json_data(response)
        page_records = data.get("lists", []) if isinstance(data, dict) else []
        if not isinstance(page_records, list):
            page_records = []
        added = 0
        for item in page_records:
            if not isinstance(item, dict):
                continue
            course_id = str(item.get("course_id", ""))
            if course_id and course_id not in seen_ids:
                seen_ids.add(course_id)
                records.append(item)
                added += 1
        has_next = bool(data.get("hasNextPage")) if isinstance(data, dict) else False
        page_size_value = data.get("pageSize") if isinstance(data, dict) else None
        try:
            page_size = int(page_size_value)
        except (TypeError, ValueError):
            page_size = 10
        # The APK requests the next page when the current page is full.  The
        # server's hasNextPage/count values are stale for this endpoint, so a
        # full page must override hasNextPage=False.
        full_page = len(page_records) >= max(page_size, 10)
        debug(
            f"Course page {page}: received={len(page_records)}, added={added}, "
            f"pageSize={page_size}, hasNextPage={has_next}, full-page-fallback={full_page}"
        )
        if not page_records or added == 0 or not (has_next or full_page):
            break
        page += 1
    return records


def fetch_all_lessons_by_date(
    session: requests.Session, course_date: str, api_token: str,
) -> list[dict]:
    """Fetch every replay record exposed by the app's date-search endpoint."""
    records: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    page = 1
    while True:
        response = course_api(
            session,
            "v3/course/get-use-member-sub",
            {"course_time": course_date, "page": str(page)},
            api_token,
        )
        data = json_data(response)
        container = data.get("data", data) if isinstance(data, dict) else {}
        page_records = container.get("lists", []) if isinstance(container, dict) else []
        if not isinstance(page_records, list):
            page_records = []

        added = 0
        for item in page_records:
            if not isinstance(item, dict):
                continue
            identity = (
                str(item.get("course_id", "")),
                str(item.get("sub_id", "")),
                str(item.get("start_at", "")),
            )
            if identity not in seen:
                seen.add(identity)
                records.append(item)
                added += 1

        has_next_value = data.get("hasNextPage") if isinstance(data, dict) else None
        if has_next_value is None and isinstance(container, dict):
            has_next_value = container.get("hasNextPage")
        has_next = bool(has_next_value)
        page_size_value = container.get("pageSize") if isinstance(container, dict) else None
        try:
            page_size = int(page_size_value)
        except (TypeError, ValueError):
            page_size = 10
        full_page = len(page_records) >= max(page_size, 10)
        debug(
            f"Date page {page}: received={len(page_records)}, added={added}, "
            f"pageSize={page_size}, hasNextPage={has_next}, "
            f"full-page-fallback={full_page}"
        )
        if not page_records or added == 0 or not (has_next or full_page):
            break
        page += 1
    return records


MAX_DATE_RANGE_DAYS = 31


def parse_course_dates(value: str) -> list[str]:
    text = value.strip()
    if ".." in text:
        start_text, end_text = (part.strip() for part in text.split("..", 1))
    else:
        start_text = end_text = text
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", start_text) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}", end_text
    ):
        raise ValueError(f"Invalid date: {text}. Expected YYYY-MM-DD or START..END.")
    try:
        start = date.fromisoformat(start_text)
        end = date.fromisoformat(end_text)
    except ValueError as exc:
        raise ValueError(
            f"Invalid date: {text}. Expected YYYY-MM-DD or START..END."
        ) from exc
    if start > end:
        raise ValueError("Date range start must not be after end.")
    days = (end - start).days + 1
    if days > MAX_DATE_RANGE_DAYS:
        raise ValueError(
            f"Date range too long: {days} days (max {MAX_DATE_RANGE_DAYS})."
        )
    return [(start + timedelta(days=offset)).isoformat() for offset in range(days)]


def dedupe_date_records(records: list[dict]) -> list[dict]:
    unique: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for item in records:
        if not isinstance(item, dict):
            continue
        identity = (
            str(item.get("course_id", "")),
            str(item.get("sub_id", "")),
            str(item.get("start_at", "")),
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(item)
    return unique


def find_hidden_course_ids(
    session: requests.Session, records: list[dict], api_token: str,
) -> set[str]:
    if not records:
        return set()
    try:
        courses = fetch_all_courses(session, "", api_token)
    except requests.RequestException as exc:
        print(f"Could not load course list for hidden-course tagging: {type(exc).__name__}.")
        debug(describe_exception(exc))
        return set()
    known_ids = {
        str(item.get("course_id"))
        for item in courses
        if isinstance(item, dict) and item.get("course_id")
    }
    hidden_ids = {
        str(item.get("course_id"))
        for item in records
        if isinstance(item, dict) and item.get("course_id")
        and str(item.get("course_id")) not in known_ids
    }
    if hidden_ids:
        print(
            f"Course search returned {len(known_ids)} course(s); "
            f"{len(hidden_ids)} date course(s) are missing from it."
        )
    return hidden_ids


def offer_subject_download(
    session: requests.Session, api_token: str, media_cookie: str,
    course_id: str, subject_id: str, course_name: str = "",
    replay_title: str = "",
) -> None:
    response = course_api(
        session,
        "v3/course/get-course-sub-detail",
        {"course_id": course_id, "sub_id": subject_id},
        api_token,
    )
    show_response(response, response.text)
    video_data = json_data(response)
    media_candidates = extract_media_candidates(video_data)
    video_record = video_data.get("data", video_data) if isinstance(video_data, dict) else {}
    if isinstance(video_record, dict):
        course_name = str(video_record.get("course_name") or course_name)
        replay_title = str(video_record.get("title") or replay_title or subject_id)
    default_name = safe_filename(
        f"{course_name or course_id}_{replay_title or subject_id}"
    ) + ".mp4"
    debug("Media Cookie available:", "yes (value hidden)" if media_cookie else "no")
    probe_and_optionally_download(session, media_candidates, media_cookie, default_name)


def run_date_search(
    session: requests.Session, api_token: str, media_cookie: str,
    course_filter: str = "",
) -> None:
    default_date = (date.today() - timedelta(days=1)).isoformat()
    raw_dates = input(
        f"Course date YYYY-MM-DD or START..END [{default_date}]: "
    ).strip() or default_date
    try:
        course_dates = parse_course_dates(raw_dates)
    except ValueError as exc:
        print(exc)
        return
    date_records: list[dict] = []
    for course_date in course_dates:
        if len(course_dates) > 1:
            print(f"Fetching date {course_date}...")
        date_records.extend(
            fetch_all_lessons_by_date(session, course_date, api_token)
        )
    date_records = dedupe_date_records(date_records)
    if course_filter:
        matches = [
            item for item in date_records
            if course_filter.lower() in str(item.get("course_name", "")).lower()
        ]
        if matches:
            print(f"Date records matching {course_filter!r}: {len(matches)}")
            date_records = matches
        elif date_records:
            print(
                f"No date records matched {course_filter!r}; "
                f"showing all {len(date_records)} record(s)."
            )
    hidden_course_ids = find_hidden_course_ids(session, date_records, api_token)
    print_date_records(date_records, hidden_course_ids)
    if not date_records:
        print("No date records to select.")
        return
    subject_id = select_record_value(
        date_records,
        "Record number or sub_id to inspect (empty to stop): ",
        "sub_id",
    )
    if not subject_id:
        return
    selected = next(
        (
            item for item in date_records
            if isinstance(item, dict) and str(item.get("sub_id", "")) == subject_id
        ),
        None,
    )
    if selected is None:
        print(f"No matching record: {subject_id}")
        return
    status = str(selected.get("sub_status", ""))
    if status != "6":
        print(
            f"Warning: status={status} "
            f"({PLAYBACK_STATUS_LABELS.get(status, 'unknown')}); "
            "trying playback detail anyway."
        )
    offer_subject_download(
        session,
        api_token,
        media_cookie,
        str(selected.get("course_id", "")),
        subject_id,
        str(selected.get("course_name", "")),
        str(selected.get("sub_name", "")),
    )


def main(argv: list[str] | None = None) -> int:
    global VERBOSE
    parser = argparse.ArgumentParser(description="Debug PKU playback login and download replay")
    parser.add_argument("-v", "--verbose", action="store_true", help="show HTTP/API/ffmpeg debug output")
    args = parser.parse_args(argv)
    VERBOSE = args.verbose
    session = requests.Session()

    restore = input("Use the last saved login session? [Y/n]: ").strip().lower()
    restored = restore not in {"n", "no"}
    if restored:
        restored = load_login_cookies(session) and saved_login_is_valid(session)
        if restored:
            print("Restored the saved login session.")
        else:
            print("No valid saved login session; starting a new login.")

    debug("== 1. Passport entry ==")
    response = request(
        session,
        "GET",
        PASSPORT + "/auth/login?redirect=" + PASSPORT + "/auth/app-login",
    )
    show_response(response, response.text)
    parser = HiddenInputs()
    parser.feed(response.text)
    oauth_form = {
        "appName": parser.values.get("appName", ""),
        "appID": parser.values.get("appID", ""),
        "redirectUrl": parser.values.get("redirectUrl", PASSPORT),
    }
    debug(f"IAAA form: appID={oauth_form['appID']}, redirectUrl={oauth_form['redirectUrl']}")

    debug("== 2. IAAA OAuth page ==")
    response = request(session, "POST", IAAA + "/oauth.jsp", data=oauth_form)
    show_response(response, response.text)
    parser = HiddenInputs()
    parser.feed(response.text)
    appid = parser.values.get("appid") or oauth_form["appID"]

    debug("== 3. IAAA public key ==")
    response = request(session, "GET", IAAA + "/getPublicKey.do")
    show_response(response, response.text)
    key_data = response.json()
    public_key = RSA.import_key(key_data["key"])

    if not restored:
        account = input("Account: ")
        password = getpass.getpass("Password: ")
        encrypted = PKCS1_v1_5.new(public_key).encrypt(password.encode("utf-8"))
        password = ""

    if not restored:
        debug("== 4. IAAA login (credentials are not printed) ==")
        login_form = {
            "appid": appid,
            "userName": account,
            "password": base64.b64encode(encrypted).decode("ascii"),
            "randCode": "",
            "smsCode": "",
            "otpCode": "",
            "remTrustChk": "false",
            "redirUrl": oauth_form["redirectUrl"],
        }
        response = request(session, "POST", IAAA + "/oauthlogin.do", data=login_form)
        body = response.text
        show_response(response, body)
        result = response.json()
        if not result.get("success"):
            print("Login did not succeed. Paste this output only.")
            return 2

        token = str(result.get("token", ""))
        debug(f"IAAA token received: yes (length {len(token)}, value hidden)")

        callback = PASSPORT + "/?_rand=debug&token=" + quote(token, safe="")
        debug("== 5. Passport token callback ==")
        response = request(session, "GET", callback)
        callback_body = response.text
        show_response(response, callback_body)
        debug("Callback contains PKULoginSuccess:", "PKULoginSuccess" in callback_body)
        debug("Final session cookie metadata:")
        for cookie in sorted(session.cookies, key=lambda c: c.name):
            debug(
                f"  {cookie.name}: length={len(cookie.value)}, "
                f"domain={cookie.domain}, path={cookie.path}, secure={cookie.secure}"
            )
        show_callback_clues(callback_body)
        if save_login_cookies(session):
            print(f"Encrypted login state saved locally: {auth_directory()}")
        else:
            print("Could not save encrypted login state; login state was not saved.")
    debug("== 6. Authenticated course API probe ==")
    api_params = {
        "page": "1",
        "tenantid": "d438cafb4c34b3b49b3a523bbef50203",
        "tenantId": "d438cafb4c34b3b49b3a523bbef50203",
        "api_version": "3.12.0",
        "app_id": "50",
        "client": "android",
    }
    api_params["sign"] = api_sign(api_params)
    for cookie_name in ("_token", "_token2"):
        api_token = next((c.value for c in session.cookies if c.name == cookie_name), "")
        response = request(
            session,
            "GET",
            "https://yjapise.pku.edu.cn/courseapi/v3/course/get-use-member",
            params=api_params,
            headers={"token": api_token, "urlname": "courseapi"},
        )
        debug(f"Token probe: {cookie_name} (value hidden)")
        show_response(response, response.text)

    api_token = next((c.value for c in session.cookies if c.name == "_token2"), "")
    media_cookie = next((c.value for c in session.cookies if c.name == "_token"), "")
    debug("== 7. Course and playback probe ==")
    search = input("Course search (empty for all, 'd' for date): ").strip()
    if search.lower() in {"d", "date"}:
        run_date_search(session, api_token, media_cookie)
    else:
        course_records = fetch_all_courses(session, search, api_token)
        print_course_records({"lists": course_records})
        if not course_records:
            print(f"No courses matched {search!r}. Falling back to date search.")
            run_date_search(
                session, api_token, media_cookie, course_filter=search,
            )
        else:
            choice = input(
                "Course number or course_id (empty to stop, 'd' for date): "
            )
            if choice.strip().lower() in {"d", "date"}:
                run_date_search(
                    session, api_token, media_cookie, course_filter=search,
                )
            else:
                course_id = resolve_record_choice(
                    course_records, choice, "course_id",
                )
                if course_id:
                    response = course_api(
                        session,
                        "v3/course/get-course-detail",
                        {"course_id": course_id},
                        api_token,
                    )
                    show_response(response, response.text)
                    subject_data = json_data(response)
                    subject_container = subject_data
                    if isinstance(subject_container, dict) and isinstance(
                        subject_container.get("data"), dict
                    ):
                        subject_container = subject_container["data"]
                    subjects = (
                        subject_container.get("sub_list", [])
                        if isinstance(subject_container, dict)
                        else []
                    )
                    if not isinstance(subjects, list):
                        subjects = []
                    print("Scanning for hidden recordings...")
                    hidden_subjects = scan_hidden_subjects(
                        session, course_id, subjects, api_token,
                    )
                    print_sub_records(subject_data, hidden_subjects)
                    all_subjects = subjects + hidden_subjects
                    subject_id = select_record_value(
                        all_subjects,
                        "Lesson number or sub_id to inspect (empty to stop): ",
                        "id",
                    )
                    if subject_id:
                        replay_title = next(
                            (
                                str(item.get("sub_title") or "")
                                for item in all_subjects
                                if isinstance(item, dict)
                                and str(item.get("id")) == subject_id
                            ),
                            "",
                        )
                        selected_course_name = next(
                            (
                                str(item.get("course_name") or "")
                                for item in course_records
                                if isinstance(item, dict)
                                and str(item.get("course_id")) == course_id
                            ),
                            "",
                        )
                        offer_subject_download(
                            session,
                            api_token,
                            media_cookie,
                            course_id,
                            subject_id,
                            selected_course_name,
                            replay_title,
                        )
    print("Done. No password, token, or cookie value was printed.")
    return 0


def probe_and_optionally_download(
    session: requests.Session, candidates: list[dict], media_cookie: str,
    default_name: str = "replay.mp4",
) -> None:
    if not candidates:
        print("No media URL returned.")
        return
    debug("== 8. Media probe/download ==")
    headers = {"Cookie": f"_token={media_cookie}"}
    media = None
    for candidate in candidates:
        parsed = urlsplit(candidate["url"])
        debug(f"Probing {candidate['kind']} candidate: {parsed.netloc}{parsed.path}")
        media = probe_media(session, candidate, headers)
        if media:
            break
    if not media:
        print("No usable media URL was returned; download skipped.")
        return
    if media["kind"] == "hls":
        print(
            f"Found HLS replay: {media['label']}, "
            f"duration {format_time(media['duration'])}"
        )
    else:
        size = f" {format_bytes(media['size'])}" if media["size"] else ""
        print(f"Found direct media: {media['label']} ({media['content_type']}{size})")
    answer = input("Download/resume this replay? [y/N]: ").strip().lower()
    if answer != "y":
        return
    output = input(f"Output file [{default_name}]: ").strip() or default_name
    output_path = Path(output).expanduser()
    try:
        if media["kind"] == "hls":
            ffmpeg = shutil.which("ffmpeg")
            if not ffmpeg:
                print("ffmpeg not found in PATH; HLS download requires it.")
                return
            resumable_hls_download(
                session, media["playlist_url"], media_cookie, output_path, ffmpeg,
                (media["playlist_url"], media["body"]),
            )
        else:
            resumable_file_download(
                session, media["url"], media_cookie, output_path, media["size"],
            )
    except Exception as exc:
        print(f"Download failed: {type(exc).__name__}; partial data was kept for resume.")
        debug(describe_exception(exc))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.RequestException as exc:
        print(f"Network error: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
