#!/usr/bin/env python3
"""Advisory checks over a values file.

values.schema.json rejects malformed values, and templates/validate-values.yaml
rejects combinations that cannot work. This catches the third category: values
that are well-formed, render fine, and are still wrong in production.

ERROR findings fail the run. WARN findings are advisory and do not.

Usage: tools/values-doctor.py <values.yaml> [<values.yaml> ...]
"""

import math
import re
import sys

import yaml

# Go duration units in seconds. time.ParseDuration accepts a concatenation of
# them ("1h30m"), which is what values.schema.json's pattern allows through.
_DURATION_UNITS = {
    "ns": 1e-9,
    "us": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
}


def get(values, path, default=None):
    node = values
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return default if node is None else node


# A setting can arrive three ways: the typed value, the config/secret
# passthrough, or extraEnv. Judging only the typed value makes the doctor miss
# exactly the production mistakes it exists to catch.
def effective(values, path, env_name, default=None):
    # Checked strongest first, mirroring the chart's documented precedence
    # (chart defaults < config/secret via envFrom < extraEnv, because env
    # entries beat envFrom and extraEnv lands last in env).
    for entry in get(values, "extraEnv", []) or []:
        if isinstance(entry, dict) and entry.get("name") == env_name and "value" in entry:
            return entry["value"]
    for source in ("config", "secret"):
        flat = flatten(get(values, source, {}) or {})
        if env_name in flat:
            return flat[env_name]
    return get(values, path, default)


def flatten(node, prefix=""):
    """Mirror of the chart's toEnvVars helper: nested maps join with _, upper."""
    out = {}
    if not isinstance(node, dict):
        return out
    for key, value in node.items():
        name = f"{prefix}_{key}".upper() if prefix else str(key).upper()
        if isinstance(value, dict):
            out.update(flatten(value, name))
        elif isinstance(value, list):
            out[name] = ",".join(str(v) for v in value)
        elif value is not None:
            out[name] = str(value)
    return out


def parse_duration(value):
    """Seconds in a Go duration string, or None when it is not one."""
    text = str(value).strip()
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(ns|us|ms|s|m|h)", text)
    if not parts or "".join(n + u for n, u in parts) != text:
        return None
    return sum(float(number) * _DURATION_UNITS[unit] for number, unit in parts)


def budget_blocks_eviction(budget, replicas, is_min):
    """True when the budget permits zero disruptions.

    Both fields accept an int or a percentage string, so "100%" and "0" are as
    blocking as the integer forms and have to be parsed rather than compared.
    """
    if budget is None or budget == "":
        return False
    if isinstance(budget, str) and budget.strip().endswith("%"):
        try:
            pct = float(budget.strip().rstrip("%"))
        except ValueError:
            return False
        # Kubernetes rounds a percentage minAvailable UP and a percentage
        # maxUnavailable DOWN, so "50%" of one replica requires all of it and
        # blocks every eviction. Comparing the raw percentage misses that.
        if is_min:
            return math.ceil(pct * replicas / 100.0) >= replicas
        return math.floor(pct * replicas / 100.0) <= 0
    try:
        value = int(budget)
    except (TypeError, ValueError):
        return False
    return value >= replicas if is_min else value <= 0


def truthy(value):
    return str(value).strip().lower() in ("true", "1", "yes")


def check(values):
    """Yield (level, path, message)."""
    findings = []

    def error(path, msg):
        findings.append(("ERROR", path, msg))

    def warn(path, msg):
        findings.append(("WARN", path, msg))

    # A PDB is judged against the replica count that actually applies: under an
    # autoscaler the chart omits replicas entirely and minReplicas is the floor.
    if get(values, "autoscaling.enabled", False):
        replicas = int(get(values, "autoscaling.minReplicas", 1))
    else:
        replicas = int(get(values, "replicaCount", 1))

    # Credentials that end up readable in the pod spec. The store DSN is not
    # among them: the chart always reads it through a secretKeyRef, so an
    # inlined postgres.url reaches the release but never the pod spec.
    if get(values, "clair.psk") and not get(values, "clair.existingSecret"):
        warn(
            "clair.psk",
            "is the key that authenticates every call to Clair, inlined into "
            "the release. Use clair.existingSecret for anything longer-lived "
            "than a test install.",
        )
    if get(values, "api.tls.key") and not get(values, "api.tls.existingSecret"):
        warn(
            "api.tls.key",
            "inlines a private key into the release. Use api.tls.existingSecret, "
            "which takes a cert-manager Secret directly.",
        )
    if get(values, "imageCredentials.create") and get(values, "imageCredentials.password"):
        warn(
            "imageCredentials.password",
            "is stored in the release. Prefer image.pullSecrets with a Secret "
            "you own.",
        )

    # A budget that can never be satisfied blocks every drain.
    if get(values, "podDisruptionBudget.enabled", False):
        min_available = get(values, "podDisruptionBudget.minAvailable")
        max_unavailable = get(values, "podDisruptionBudget.maxUnavailable")
        if budget_blocks_eviction(min_available, replicas, is_min=True):
            error(
                "podDisruptionBudget.minAvailable",
                f"{min_available} against {replicas} replica(s) leaves no pod "
                "evictable, which blocks node drains indefinitely.",
            )
        if budget_blocks_eviction(max_unavailable, replicas, is_min=False):
            error(
                "podDisruptionBudget.maxUnavailable",
                f"{max_unavailable} leaves no pod evictable, which blocks node "
                "drains indefinitely.",
            )
        if replicas < 2 and not get(values, "autoscaling.enabled", False):
            warn(
                "podDisruptionBudget.enabled",
                f"with replicaCount {replicas} protects nothing.",
            )

    # Scaling below the autoscaler's floor is silently overridden. Judge the
    # raw replicaCount here: `replicas` was already reassigned from
    # minReplicas when autoscaling is on, so comparing it would never fire.
    if get(values, "autoscaling.enabled", False):
        min_replicas = int(get(values, "autoscaling.minReplicas", 1))
        replica_count = int(get(values, "replicaCount", min_replicas))
        if "replicaCount" in values and replica_count != min_replicas:
            warn(
                "replicaCount",
                f"{replica_count} is ignored while autoscaling is enabled; the "
                f"autoscaler starts from minReplicas {min_replicas}.",
            )

    # Trust settings that defeat each other. insecureSkipVerify applies to
    # every outbound connection, so a mounted CA bundle next to it is trusted
    # by nothing: whoever added the bundle meant to verify.
    insecure = truthy(
        effective(values, "tls.insecureSkipVerify", "SCANNER_TLS_INSECURE_SKIP_VERIFY", False)
    )
    if insecure:
        ca = get(values, "extraCA.existingSecret") or get(values, "extraCA.existingConfigMap")
        if ca:
            error(
                "tls.insecureSkipVerify",
                "is set while extraCA mounts a CA bundle. Verification is off, "
                "so the bundle is never consulted; keep one or the other.",
            )
        else:
            warn(
                "tls.insecureSkipVerify",
                "skips certificate verification for every outbound connection, "
                "Clair and the registry both. If this is for a private CA, use "
                "extraCA instead.",
            )

    # An encrypted front door in front of a plaintext back door.
    clair_url = str(effective(values, "clair.url", "SCANNER_CLAIR_URL", "http://clair:6060"))
    if get(values, "api.tls.enabled", False) and clair_url.startswith("http://"):
        warn(
            "clair.url",
            "is plaintext while the adapter's own API serves TLS. Scan requests "
            "are encrypted, the manifest and report traffic to Clair is not.",
        )

    # The multi-replica case is a render-time ERROR (templates/validate-values.yaml),
    # so only the single-replica warning is left to make.
    if str(effective(values, "store.backend", "SCANNER_STORE_BACKEND", "postgres")) == "memory":
        warn(
            "store.backend",
            "memory keeps scan reports in one pod and loses them on restart. "
            "It is a development backend; use postgres for anything Harbor "
            "polls.",
        )

    # Harbor's report polling has no total timeout - it restarts its own timer
    # on every 302 - so the adapter's scan job TTL is the effective deadline on
    # a queued job. A TTL under the index deadline turns a slow-but-successful
    # scan into a 404.
    ttl = parse_duration(
        effective(values, "store.scanJobTTL", "SCANNER_STORE_SCAN_JOB_TTL", "1h")
    )
    index_timeout = parse_duration(
        effective(values, "clair.indexTimeout", "SCANNER_CLAIR_INDEX_TIMEOUT", "10m")
    )
    if ttl is not None and index_timeout is not None and ttl <= index_timeout:
        warn(
            "store.scanJobTTL",
            "is not longer than clair.indexTimeout, so a scan that indexes for "
            "its full deadline expires before Harbor can collect the report.",
        )

    return findings


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    failed = False
    for path in argv[1:]:
        values = yaml.safe_load(open(path)) or {}
        findings = check(values)
        print(f"== {path}", file=sys.stderr)
        if not findings:
            print("   no findings", file=sys.stderr)
        for level, where, message in findings:
            print(f"   {level} {where}: {message}", file=sys.stderr)
            if level == "ERROR":
                failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
