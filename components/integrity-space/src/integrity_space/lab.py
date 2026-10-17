"""Provision synthetic events via SeedCatalog, never copy the owner's archive."""
from __future__ import annotations
import argparse
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from integrity_guardian.seed_catalog import SeedCatalog


def lab_events(slug: str) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    def node(kind, key, title, definition=None):
        return {"kind": kind, "id": key, "title": title, **({"definition": definition} if definition else {})}
    def link(source, relation, target, claim="CURRENT", stale=None):
        return {"source": {"kind": source[0], "id": source[1]}, "relation": relation,
                "target": {"kind": target[0], "id": target[1]}, "claim_state": claim,
                **({"stale_after": stale} if stale else {})}
    def event(eid, action, summary, details):
        return {"id": eid, "event_uid": f"{slug}-event-{eid}", "ts_utc": now,
                "actor": "isolated-space-lab", "session_id": "space-lab-session",
                "level": "info", "action": action, "summary": summary, "details": details, "tags": ["synthetic", "space-lab"]}
    root = ("subsystem", slug)
    task = ("task", "review-interface")
    return [
        event(1, "seed_doctrine_declared", "Изолированный проект для проверки интерфейса Integrity", {
            "truth_status": "observed", "memory_nodes": [node("subsystem", slug, "Проверка частной интеграции")],
            "memory_links": []}),
        event(2, "agent_change_started", "Проверить маршрут выбранной задачи", {
            "task_id": task[1], "result": "active", "owner": "lab-owner", "scope": "Только тестовые данные; без отправки исполнителю",
            "memory_nodes": [node("task", task[1], "Проверить маршрут выбранной задачи"),
                node("decision", "local-custody", "Ядро и память остаются у владельца", "Передавать только ограниченный контекст выбранной задачи."),
                node("concept", "no-private-export", "Не экспортировать приватную историю"),
                node("decision", "old-layout", "Старое расположение панели")],
            "memory_links": [link(root, "concerns", task), link(root, "concerns", ("decision", "local-custody")),
                link(root, "concerns", ("concept", "no-private-export")),
                link(task, "depends-on", ("decision", "local-custody")),
                link(task, "concerns", ("concept", "no-private-export")),
                link(task, "refers-to", ("decision", "old-layout"), "STALE", "2020-01-01T00:00:00Z")]}),
        event(3, "agent_change_started", "Проверить доступность источников", {
            "task_id": "verify-sources", "result": "active", "owner": "lab-observer", "memory_nodes": [],
            "memory_links": [link(root, "concerns", ("task", "verify-sources"))]}),
        event(4, "agent_executor_claim", "Исполнитель заявил: интерфейс готов; независимая проверка ещё нужна", {
            "task_id": task[1], "result": "active", "request_id": "lab-request-1", "destination_id": "lab-destination-1",
            "result_id": "lab-result-claim-1", "truth_status": "claimed", "memory_nodes": [node("evidence", "lab-result-claim-1", "Заявленный результат · не проверен")],
            "memory_links": [link(task, "cites", ("evidence", "lab-result-claim-1"), "UNKNOWN")]}),
        event(5, "agent_change_complete", "Наблюдатель проверил источники тестового проекта", {
            "task_id": "verify-sources", "result": "verified", "truth_status": "observed", "memory_nodes": [node("evidence", "source-check", "Источники проверены наблюдателем")],
            "memory_links": [link(("task", "verify-sources"), "cites", ("evidence", "source-check"))]}),
        event(6, "agent_change_started", "Unrelated history marker: FOREIGN-ARCHIVE-MARKER", {
            "task_id": "unrelated-task", "result": "active", "memory_nodes": [], "memory_links": []}),
    ]


def provision(root: Path) -> Path:
    root = root.absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows = []
    for slug, label in (("space-lab-interface", "Частная интеграция · тестовый проект"), ("space-lab-empty", "Пустой тестовый проект")):
        state = root / slug
        state.mkdir(mode=0o700)
        catalog = state / "catalog.sqlite3"
        SeedCatalog(catalog).import_events(lab_events(slug) if slug.endswith("interface") else lab_events(slug)[:1],
                                          source_namespace=f"seed://project/{slug}")
        catalog.chmod(0o600)
        rows.append({"id": slug, "label": label, "catalog": str(catalog)})
    config = root / "projects.json"
    config.write_text(json.dumps({"version": 1, "mode": "isolated-lab", "projects": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    config.chmod(0o600)
    transport = root / "transport.token"
    transport.write_text(secrets.token_urlsafe(32), encoding="utf-8")
    transport.chmod(0o600)
    return config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(provision(args.root))


if __name__ == "__main__":
    main()
