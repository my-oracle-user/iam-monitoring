#!/usr/bin/env python3
import argparse
import sys

from job_runner import (
    _read_state_file,
    _job_state_path,
    _now_utc_iso,
    _write_state_file,
    collect_environment_now,
    run_due_collection_jobs,
)


def mark_job_finished(db_path, environment_id, trigger, exit_code):
    existing = _read_state_file(_job_state_path(db_path, environment_id))
    _write_state_file(
        _job_state_path(db_path, environment_id),
        {
            "status": "finished" if exit_code == 0 else "failed",
            "started_at": existing.get("started_at", _now_utc_iso()),
            "finished_at": _now_utc_iso(),
            "last_exit": str(exit_code),
            "pid": "",
            "trigger": trigger,
        },
    )


def main():
    parser = argparse.ArgumentParser(description="Run IAM environment collection jobs.")
    parser.add_argument("--db-path", required=True, help="SQLite registry path")
    parser.add_argument("--env-id", help="Environment id for a single collector run")
    parser.add_argument("--trigger", default="manual", help="Job trigger label")
    parser.add_argument("--scheduler", action="store_true", help="Launch any due environment collector jobs")
    args = parser.parse_args()

    if args.scheduler:
        launched = run_due_collection_jobs(args.db_path)
        print("Scheduler launched {0} collector job(s).".format(len(launched)))
        for item in launched:
            label = "started" if item.get("started") else "already running"
            if item.get("error"):
                label = "error: {0}".format(item.get("error"))
            print("  - {0} ({1}): {2}".format(item.get("environmentName") or item.get("environmentId"), item.get("environmentId"), label))
        return 0

    if not args.env_id:
        raise ValueError("--env-id is required unless --scheduler is used.")

    print("Starting environment collector for {0}.".format(args.env_id))
    exit_code = 0
    try:
        dashboard = collect_environment_now(args.db_path, args.env_id, trigger=args.trigger)
        print(
            "Collector finished for {0} with status {1} at {2}.".format(
                args.env_id,
                dashboard.get("status") or "unknown",
                dashboard.get("generatedAtLocal") or dashboard.get("generatedAt") or "n/a",
            )
        )
    except Exception as exc:
        exit_code = 1
        print("Collector failed for {0}: {1}".format(args.env_id, exc))
    mark_job_finished(args.db_path, args.env_id, args.trigger, exit_code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
