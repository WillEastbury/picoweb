#!/usr/bin/env python3
"""bench_load.py -- lightweight persistent-connection HTTP load generator
for picowal, using only the stdlib (no wrk/hey/ab available in this
environment, and no external packages should be installed for a quick
benchmark).

Unlike curl-per-request bash loops, each worker thread opens ONE
http.client.HTTPConnection and reuses it (keep-alive) for its entire
share of requests, so the measured throughput reflects picoweb's actual
request handling rather than TCP-handshake/process-spawn overhead.
"""
import argparse
import http.client
import json
import sys
import threading
import time


def worker(host, port, token, method, path_fn, body_fn, n, results, idx):
    conn = http.client.HTTPConnection(host, port, timeout=5)
    ok = 0
    err = 0
    for i in range(n):
        path = path_fn(idx, i)
        body = body_fn(idx, i)
        headers = {"X-PW-Write-Token": token}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp.read()
            if 200 <= resp.status < 300 or resp.status == 204:
                ok += 1
            else:
                err += 1
        except (http.client.HTTPException, OSError):
            err += 1
            try:
                conn.close()
            except Exception:
                pass
            conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.close()
    results[idx] = (ok, err)


def run_phase(name, host, port, token, method, path_fn, body_fn, workers, per_worker):
    results = [None] * workers
    threads = []
    t0 = time.perf_counter()
    for idx in range(workers):
        t = threading.Thread(
            target=worker,
            args=(host, port, token, method, path_fn, body_fn, per_worker, results, idx),
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0
    total_ok = sum(r[0] for r in results)
    total_err = sum(r[1] for r in results)
    total = total_ok + total_err
    rps = total / elapsed if elapsed > 0 else 0.0
    print(f"{name}: {total_ok} ok, {total_err} err, {elapsed:.3f}s elapsed, {rps:.1f} req/s")
    return total_ok, total_err, elapsed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-host", default="127.0.0.1")
    ap.add_argument("--write-port", type=int, required=True)
    ap.add_argument("--read-ports", type=int, nargs="+", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--write-workers", type=int, default=16)
    ap.add_argument("--writes-per-worker", type=int, default=300)
    ap.add_argument("--read-workers", type=int, default=16)
    ap.add_argument("--reads-per-worker", type=int, default=300)
    ap.add_argument("--pack", type=int, default=10)
    args = ap.parse_args()

    def write_path(idx, i):
        rec = idx * 10000 + i
        return f"/wal/{args.pack}/{rec}"

    def write_body(idx, i):
        rec = idx * 10000 + i
        return json.dumps({"id": f"i{rec}", "name": f"item-{rec}", "value": rec})

    run_phase(
        "writes", args.write_host, args.write_port, args.token, "PUT",
        write_path, write_body, args.write_workers, args.writes_per_worker,
    )

    query_body = "S:name,value\nF:%d\nW:value|>|0" % args.pack

    def read_path(idx, i):
        which = i % 3
        if which == 0:
            rec = (idx * 10000) + (i % args.writes_per_worker) + 1
            return f"/wal/{args.pack}/{rec}"
        elif which == 1:
            return "/wal/query"
        else:
            return "/wal/report"

    def read_body(idx, i):
        which = i % 3
        if which == 0:
            return None
        return query_body

    def read_method(idx, i):
        return "GET" if i % 3 == 0 else "POST"

    # reads: round-robin across the given ports, one worker pool per port
    port_cycle = args.read_ports
    results = [None] * args.read_workers
    threads = []
    t0 = time.perf_counter()

    def read_worker(idx):
        port = port_cycle[idx % len(port_cycle)]
        conn = http.client.HTTPConnection(args.write_host, port, timeout=5)
        ok = 0
        err = 0
        for i in range(args.reads_per_worker):
            path = read_path(idx, i)
            body = read_body(idx, i)
            method = read_method(idx, i)
            headers = {"X-PW-Write-Token": args.token}
            if body is not None:
                headers["Content-Type"] = "text/plain"
            try:
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                resp.read()
                if 200 <= resp.status < 300:
                    ok += 1
                else:
                    err += 1
            except (http.client.HTTPException, OSError):
                err += 1
                try:
                    conn.close()
                except Exception:
                    pass
                conn = http.client.HTTPConnection(args.write_host, port, timeout=5)
        conn.close()
        results[idx] = (ok, err)

    for idx in range(args.read_workers):
        t = threading.Thread(target=read_worker, args=(idx,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0
    total_ok = sum(r[0] for r in results)
    total_err = sum(r[1] for r in results)
    total = total_ok + total_err
    rps = total / elapsed if elapsed > 0 else 0.0
    print(f"reads: {total_ok} ok, {total_err} err, {elapsed:.3f}s elapsed, {rps:.1f} req/s")

    if total_err or any(r[1] for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
