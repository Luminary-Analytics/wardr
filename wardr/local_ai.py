"""Optional offline review batches over Wardr's deterministic remediation plan."""

import http.client
import json
import socket
import threading
import time


MODEL = "qwen2.5:1.5b"
# Official registry manifest for the Apache-2.0 Q4_K_M model. Pin the bytes,
# since Ollama also permits users to create a different model with this name.
_MODEL_DIGEST = "65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b"
_DOWNLOAD_SIZE = 986_000_000
_PORT = 11434
_STATUS_TIMEOUT = 2
_REVIEW_TIMEOUT = 55
_PREPARE_TIMEOUT = 15 * 60
_MAX_TASKS = 24
_MAX_SELECTIONS = 4
_MODEL_ACTION = threading.Lock()

_PRIORITIES = ("urgent", "high", "scheduled", "verify")
_SOURCES = {
    "Device check": ("device", "Review the original settings, apply the approved changes, and run a fresh device scan."),
    "Published advisory": ("software", "Review the matched versions, then reassess an updated inventory after patching."),
    "Local telemetry": ("events", "Review the source records together and document which changes were expected."),
    "Local exposure": ("network", "Confirm the purpose and owner of the local bindings, then refresh the exposure inventory."),
}
_PROMPT = (
    "Select one to four existing remediation task numbers from the table. "
    "Use each task number at most once. "
    "Include a task from the highest priority present. Priority order is urgent, high, scheduled, verify. "
    'Return only JSON in this form: {"items":[1,2,3]}.'
)


class LocalAIError(Exception):
    """Wardr could not run or validate the optional local model."""


def _interrupt_connection(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _request(path: str, data: dict | None = None, *, timeout: int, limit: int) -> dict:
    # HTTPConnection talks directly to a fixed numeric loopback address. It
    # neither resolves proxy environment settings nor follows HTTP redirects.
    deadline = time.monotonic() + timeout
    client = http.client.HTTPConnection("127.0.0.1", _PORT, timeout=timeout)
    timer = None
    try:
        client.connect()
        timer = threading.Timer(max(0, deadline - time.monotonic()), _interrupt_connection, (client.sock,))
        timer.daemon = True
        timer.start()
        if data is None:
            client.request("GET", path)
        else:
            client.request("POST", path, json.dumps(data, separators=(",", ":")),
                           {"Content-Type": "application/json"})
        with client.getresponse() as response:
            if response.status != 200:
                raise LocalAIError("Local Ollama rejected the request.")
            content = response.read(limit + 1)
    except (OSError, http.client.HTTPException) as exc:
        if time.monotonic() >= deadline or isinstance(exc, TimeoutError):
            raise LocalAIError("Local Ollama did not respond before the time limit. Try again when it is idle.") from None
        raise LocalAIError("Wardr could not reach Ollama on 127.0.0.1:11434.") from None
    finally:
        if timer is not None:
            timer.cancel()
        client.close()
    if len(content) > limit:
        raise LocalAIError("Local Ollama returned more data than Wardr can read.")
    try:
        payload = json.loads(content)
    except (ValueError, RecursionError):
        raise LocalAIError("Local Ollama returned an unreadable response.") from None
    if not isinstance(payload, dict):
        raise LocalAIError("Local Ollama returned an unreadable response.")
    return payload


def status() -> dict:
    """Return whether the reviewed model is available from the local runtime."""
    result = {
        "available": False,
        "model_ready": False,
        "model": MODEL,
        "model_size_bytes": None,
        "download_size_bytes": _DOWNLOAD_SIZE,
        "state": "runtime_unavailable",
        "message": "Start Ollama on 127.0.0.1:11434 to enable local AI review.",
    }
    try:
        response = _request("/api/tags", timeout=_STATUS_TIMEOUT, limit=512 * 1024)
    except LocalAIError:
        return result
    models = response.get("models")
    if not isinstance(models, list):
        return result
    result.update(
        available=True,
        state="model_missing",
        message="Download the Wardr model while online with wardr model pull.",
    )
    for entry in models:
        if not isinstance(entry, dict) or (entry.get("model") or entry.get("name")) != MODEL:
            continue
        digest = entry.get("digest")
        if not isinstance(digest, str) or digest.removeprefix("sha256:") != _MODEL_DIGEST:
            result.update(
                state="model_unverified",
                message="The named Ollama model does not match the official model reviewed for Wardr.",
            )
            return result
        size = entry.get("size")
        result.update(
            model_ready=True,
            model_size_bytes=size if type(size) is int and size > 0 else None,
            state="ready",
            message="The verified model is ready for offline review.",
        )
        break
    return result


def prepare_model() -> dict:
    """Explicitly ask Ollama to download the approved model while online."""
    if not _MODEL_ACTION.acquire(blocking=False):
        raise LocalAIError("A local AI action is already in progress.")
    try:
        before = status()
        if before["model_ready"]:
            return before
        if before["state"] != "model_missing":
            raise LocalAIError(before["message"])
        payload = _request(
            "/api/pull", {"model": MODEL, "stream": False}, timeout=_PREPARE_TIMEOUT, limit=32 * 1024,
        )
        if payload.get("status") != "success":
            raise LocalAIError("Ollama did not complete the model download.")
        verified = status()
        if not verified["model_ready"]:
            raise LocalAIError(verified["message"])
        return verified
    finally:
        _MODEL_ACTION.release()


def _review_tasks(plan: dict) -> list[dict]:
    candidates = []
    seen = set()
    tasks = plan.get("tasks")
    if not isinstance(tasks, (list, tuple)):
        return candidates
    for task in tasks[:2000]:
        if not isinstance(task, dict):
            continue
        identifier = task.get("id")
        priority = task.get("priority")
        source = task.get("source")
        if (
            not isinstance(identifier, str) or not identifier or len(identifier) > 240 or identifier in seen
            or priority not in _PRIORITIES or not isinstance(source, str) or source not in _SOURCES
        ):
            continue
        seen.add(identifier)
        candidates.append({"id": identifier, "priority": priority, "source": source})
        if len(candidates) == _MAX_TASKS:
            break
    return candidates


def _review_request(tasks: list[dict]) -> dict:
    numbers = list(range(1, len(tasks) + 1))
    table = [
        {"item": index, "priority": task["priority"], "area": _SOURCES[task["source"]][0]}
        for index, task in enumerate(tasks, 1)
    ]
    schema = {
        "type": "object",
        "properties": {
            "items": {
                "type": "array", "minItems": 1, "maxItems": min(_MAX_SELECTIONS, len(numbers)),
                "items": {"type": "integer", "enum": numbers},
            },
        },
        "required": ["items"],
        "additionalProperties": False,
    }
    return {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": _PROMPT},
            {"role": "user", "content": json.dumps(table, separators=(",", ":"))},
        ],
        "format": schema,
        "stream": False,
        "keep_alive": 0,
        "options": {"num_ctx": 2048, "num_predict": 160, "temperature": 0},
    }


def _selections(payload: dict, tasks: list[dict]) -> list[dict]:
    error = "The local model did not return valid review batches. The original remediation plan is available."
    message = payload.get("message")
    if payload.get("done") is not True or payload.get("done_reason") == "length" or not isinstance(message, dict):
        raise LocalAIError(error)
    content = message.get("content")
    if message.get("tool_calls") or not isinstance(content, str) or len(content) > 4096:
        raise LocalAIError(error)
    try:
        output = json.loads(content)
    except (ValueError, RecursionError):
        raise LocalAIError(error) from None
    if not isinstance(output, dict) or set(output) != {"items"}:
        raise LocalAIError(error)
    numbers = output["items"]
    if (
        not isinstance(numbers, list) or not 1 <= len(numbers) <= _MAX_SELECTIONS
        or any(type(index) is not int or not 1 <= index <= len(tasks) for index in numbers)
        or len(numbers) != len(set(numbers))
    ):
        raise LocalAIError(error)

    batches = {}
    for index in numbers:
        row = tasks[index - 1]
        batches.setdefault((row["source"], row["priority"]), []).append(row["id"])
    selections = [
        {
            "priority": priority,
            "source": source,
            "item_ids": identifiers,
            "explanation": _SOURCES[source][1],
        }
        for (source, priority), identifiers in batches.items()
    ]
    selections.sort(key=lambda selection: _PRIORITIES.index(selection["priority"]))
    highest = min(_PRIORITIES.index(task["priority"]) for task in tasks)
    if _PRIORITIES.index(selections[0]["priority"]) != highest:
        raise LocalAIError(error)
    return selections


def review(plan: dict) -> dict:
    """Suggest review batches without sending evidence text or making changes."""
    tasks = _review_tasks(plan)
    if not tasks:
        return {"model": MODEL, "reviewed_count": 0, "selections": []}
    if not _MODEL_ACTION.acquire(blocking=False):
        raise LocalAIError("A local AI action is already in progress.")
    try:
        readiness = status()
        if not readiness["model_ready"]:
            raise LocalAIError(readiness["message"])
        response = _request("/api/chat", _review_request(tasks), timeout=_REVIEW_TIMEOUT, limit=32 * 1024)
        return {"model": MODEL, "reviewed_count": len(tasks), "selections": _selections(response, tasks)}
    finally:
        _MODEL_ACTION.release()
