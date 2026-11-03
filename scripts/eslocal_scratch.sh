#!/usr/bin/env bash
# A throwaway Elasticsearch node like es-local (same image 8.19.12, single node, security and
# TLS on by auto-configuration), for the es-local tests that plant their own data (Q-F4's
# batch-1 scenarios) in a checkout without data/ (the replica's CA and password live there).
# It never touches the replica's container or volume (argus-es-local, argus-esdata): its own
# name, port 59210 on the loopback, no volume, a random password, removed on exit.
#
#   scripts/heavy.sh --mem 3G --label "es scratch" scripts/eslocal_scratch.sh \
#       tests/integration/eslocal/test_batch1_eslocal.py
#
# Run it through scripts/heavy.sh (D-110). Arguments go to pytest.
set -euo pipefail
export DOCKER_CONTEXT=default
name=argus-es-scratch-$$
port=${ESLOCAL_SCRATCH_PORT:-59210}
dir=$(mktemp -d)
chmod 700 "$dir"
password=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$dir"
}
trap cleanup EXIT
docker run -d --name "$name" -p "127.0.0.1:$port:9200" \
  -e discovery.type=single-node -e "ES_JAVA_OPTS=-Xms384m -Xmx384m" \
  -e "ELASTIC_PASSWORD=$password" -e xpack.ml.enabled=false \
  -e cluster.routing.allocation.disk.threshold_enabled=false \
  --memory 1200m --memory-swap 1200m \
  docker.elastic.co/elasticsearch/elasticsearch:8.19.12 >/dev/null
for _ in $(seq 1 120); do
  if docker cp "$name:/usr/share/elasticsearch/config/certs/http_ca.crt" "$dir/ca.crt" \
      >/dev/null 2>&1 \
    && curl -fsS --cacert "$dir/ca.crt" -u "elastic:$password" \
      "https://127.0.0.1:$port/_cluster/health?wait_for_status=yellow&timeout=1s" >/dev/null 2>&1
  then
    ready=1
    break
  fi
  sleep 2
done
if [[ -z ${ready:-} ]]; then
  echo "eslocal_scratch: the node did not come up" >&2
  docker logs --tail 20 "$name" >&2 || true
  exit 1
fi
ESLOCAL_URL="https://127.0.0.1:$port" ESLOCAL_CA="$dir/ca.crt" \
  ESLOCAL_PASSWORD="$password" uv run pytest -q -p no:cacheprovider "$@"
