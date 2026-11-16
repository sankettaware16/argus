#!/usr/bin/env bash
# Credential custody (Q-A5, plan §7.9, DQ30 (a)): ARGUS's services as their own system users,
# each with only its own secrets, from root-owned files by LoadCredential=, running a read-only
# copy of an approved tag. The user's production step (D-109): run it as root, at a checkpoint.
#
#   sudo bash deploy/custody/install.sh --check                  # what is in place; changes nothing
#   sudo bash deploy/custody/install.sh --tag q-a5-approved --commit <its full hash>
#
# It makes, and on every later run only checks or completes (idempotent):
#   1. the group argus and the system users argus-svc, argus-web, argus-writer (no login, no home);
#   2. /etc/argus (credentials/ root's, each file 0600; argus.env and data/ root:argus 0640),
#      /opt/argus/releases, /var/lib/argus-backups (root's, 0700);
#   3. the deploy copy /opt/argus/releases/<tag>-<commit>: `git archive` of the commit the tag
#      names (it must be the one you approved), taken from a fresh root-owned repository that the
#      checkout's owner hands a bundle of the tag (root never runs git in the checkout), its own
#      virtualenv from uv.lock (no dev tools; ARGUS itself from the release's own src/, no link
#      back to a checkout), then root's with no write bit; /opt/argus/current points at it;
#   4. the secrets and files from the checkout (--from): each secret of its .env, read exactly as
#      ARGUS reads it, becomes a credential; a credential already there is never replaced (rotate
#      by hand); the non-secret settings go to /etc/argus/argus.env; the SIEM CA, the web's
#      certificate and the asset map are copied. Once there, argus.env and those files are not
#      replaced from the checkout either: a difference is shown and kept until you run again with
#      --accept-settings and the digest printed with it (they decide where the services connect);
#   5. the system units of the release's deploy/custody/units and /usr/local/sbin/argus-owner,
#      then `systemctl daemon-reload`. It never enables, starts, stops or restarts anything:
#      the switch-over commands are printed at the end.
#
# Options:
#   --from DIR       the operator's checkout (default: the one holding this script)
#   --tag T --commit H   the approved tag and the hash JOURNAL.md quotes for it
#   --uv FILE        uv, a root-owned copy (default /usr/local/bin/uv) from uv's official release
#                    with its sha256 checked, never a copy of ~/.local/bin/uv (runbook §2)
#   --operator NAME  the account that runs ARGUS today (default: $SUDO_USER)
#   --accept-settings DIGEST   take the checkout's argus.env settings and files whose differences
#                    a run printed with this digest (after you reviewed them; any later change to
#                    the checkout gives another digest and nothing is taken)
#   --root DIR       tests and rehearsals: everything under DIR, run as any user but root; owners
#                    are not checked, and chown, useradd, groupadd, usermod, runuser, systemctl and
#                    uv are whatever PATH finds (the tests' stand-ins)
# Exit: 0 all in place (or done) · 1 something to do (--check) or still missing · 2 usage.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
from=$(cd "$here/../.." && pwd)
check=0 tag="" commit="" uv=/usr/local/bin/uv operator=${SUDO_USER:-} root="" accept=""
usage() { echo "usage: deploy/custody/install.sh [--check] [--from DIR] [--tag T --commit H] [--accept-settings DIGEST] [--uv FILE] [--operator NAME] [--root DIR]" >&2; exit 2; }
while (( $# )); do
  case $1 in
    --check) check=1; shift ;;
    --from|--tag|--commit|--uv|--operator|--root|--accept-settings)
      [[ -n ${2:-} ]] || usage
      case $1 in
        --from) from=$2 ;; --tag) tag=$2 ;; --commit) commit=$2 ;; --uv) uv=$2 ;;
        --operator) operator=$2 ;; --root) root=$2 ;; --accept-settings) accept=$2 ;;
      esac
      shift 2 ;;
    *) usage ;;
  esac
done
[[ -z $tag && -z $commit ]] || [[ -n $tag && -n $commit ]] || { echo "install: --tag and --commit go together" >&2; exit 2; }
[[ -z $commit || $commit =~ ^[0-9a-f]{40}$ ]] || { echo "install: --commit is the full 40-character hash" >&2; exit 2; }
[[ -z $tag || $tag =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "install: a tag name such as q-a5-approved" >&2; exit 2; }
[[ -z $accept || $accept =~ ^[0-9a-f]{16}$ ]] || { echo "install: --accept-settings takes the 16-character digest a run printed" >&2; exit 2; }
[[ -d $from ]] || { echo "install: --from $from is not a folder" >&2; exit 2; }
from=$(cd "$from" && pwd)
if [[ -n $root ]]; then
  [[ $EUID -ne 0 ]] || { echo "install: --root is for tests and rehearsals, never as root" >&2; exit 2; }
  mkdir -p "$root"; root=$(cd "$root" && pwd)
else
  [[ $EUID -eq 0 ]] || { echo "install: run it as root (sudo bash deploy/custody/install.sh ...)" >&2; exit 2; }
fi
R() { printf '%s%s' "$root" "$1"; }  # a path of the (fake) root

pending=0 warnings=0 reload=0
say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '   ok: %s\n' "$*"; }
did()  { printf '   done: %s\n' "$*"; }
todo() { printf '   to do: %s\n' "$*"; pending=$((pending + 1)); }
warn() { printf '   warning: %s\n' "$*"; warnings=$((warnings + 1)); }
die()  { printf '\nSTOPPED: %s\n' "$*" >&2; exit 1; }
owner_of() { [[ -n $root ]] && { echo "-"; return; }; stat -c '%U:%G' "$1"; }  # "-": not checked
mode_of() { stat -c '%a' "$1"; }

GROUP=argus
declare -A ROLE_OF=([argus-svc]=svc [argus-web]=web [argus-writer]=writer)
USERS=(argus-svc argus-web argus-writer)

# ----------------------------------------------------------------------------- 1. accounts
say "accounts"
have() { [[ -f $(R /etc/$1) ]] && grep -q "^$2:" "$(R /etc/$1)"; }
member() {  # member GROUP USER
  [[ -f $(R /etc/group) ]] && awk -F: -v g="$1" -v u="$2" \
    '$1 == g { n = split($4, m, ","); for (i = 1; i <= n; i++) if (m[i] == u) f = 1 } END { exit !f }' "$(R /etc/group)"
}
if have group "$GROUP"; then ok "group $GROUP"
elif (( check )); then todo "the group $GROUP"
else groupadd --system "$GROUP"; did "the group $GROUP"
fi
for user in "${USERS[@]}"; do
  if have passwd "$user"; then
    # an account of that name made by someone else must still be a system account without login
    read -r uid shell < <(awk -F: -v u="$user" '$1 == u { print $3, $7 }' "$(R /etc/passwd)")
    if (( uid == 0 || uid >= 1000 )) || [[ $shell != */nologin && $shell != */false ]]; then
      die "$user exists but is not a system account without login (uid $uid, shell $shell): fix it by hand"
    fi
    ok "user $user (uid $uid, no login)"
  elif (( check )); then todo "the system user $user"
  else
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
      --comment "ARGUS ${ROLE_OF[$user]} (Q-A5)" "$user"
    did "the system user $user"
  fi
  if member "$GROUP" "$user"; then :
  elif (( check )); then todo "$user in the group $GROUP"
  else usermod --append --groups "$GROUP" "$user"; did "$user in the group $GROUP"
  fi
done

# ----------------------------------------------------------------------------- 2. folders
say "folders"
folder() {  # folder PATH MODE OWNER:GROUP
  local path; path=$(R "$1")
  if [[ -L $path ]]; then die "$1 is a symbolic link: custody's folders are real ones"; fi
  if [[ -d $path ]]; then
    local have_mode have_owner; have_mode=$(mode_of "$path") have_owner=$(owner_of "$path")
    if [[ $have_mode == "$2" && ( $have_owner == - || $have_owner == "$3" ) ]]; then ok "$1 ($2${root:+, owner not checked})"; return; fi
    if (( check )); then todo "$1: $have_mode $have_owner, wanted $2 $3"; return; fi
  elif (( check )); then todo "$1 ($2 $3)"; return
  fi
  mkdir -p "$path"; chmod "$2" "$path"; chown "$3" "$path"
  did "$1 ($2 $3)"
}
folder /etc/argus 755 root:root
folder /etc/argus/credentials 755 root:root
folder /etc/argus/certs 755 root:root
folder /etc/argus/tls 755 root:root
folder /etc/argus/data 750 root:$GROUP
folder /opt/argus 755 root:root
folder /opt/argus/releases 755 root:root
folder /var/lib/argus-backups 700 root:root
folder /var/cache/argus-build 700 root:root

# ----------------------------------------------------------------------------- 3. deploy copy
say "deploy copy"
current=$(R /opt/argus/current)
release_name=""
if [[ -n $tag ]]; then
  release_name="$tag-${commit:0:12}"
  rel=$(R "/opt/argus/releases/$release_name")
  if [[ -f $rel/.argus-release ]] && grep -qx "commit=$commit" "$rel/.argus-release"; then
    ok "release $release_name"
  elif (( check )); then
    todo "the release $release_name (git archive of $commit, its virtualenv, read-only)"
  else
    # git never runs as root in the checkout: its settings, attributes and replacements are the
    # operator account's (review F1). Its owner bundles the tag; root fetches the bundle into a
    # fresh repository of its own (no settings but root's defaults, no replacements, every object
    # checked) and archives the approved commit from there.
    build=$(R /var/cache/argus-build)
    rm -rf "$build"/git.*
    work=$(mktemp -d "$build/git.XXXXXX")
    owner=$(stat -c '%U' "$from")
    (cd / && runuser -u "$owner" -- env -i PATH=/usr/bin:/bin HOME=/nonexistent \
      git -C "$from" bundle create --quiet - "refs/tags/$tag") >"$work/approved.bundle" \
      || die "$owner could not bundle the tag $tag of $from"
    clean() {
      env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_NO_REPLACE_OBJECTS=1 GIT_ATTR_NOSYSTEM=1 \
        git -c transfer.fsckObjects=true -c core.hooksPath=/dev/null "$@"
    }
    clean init --quiet --bare --template= "$work/approved.git" >/dev/null \
      && clean --git-dir="$work/approved.git" fetch --quiet --no-tags "$work/approved.bundle" "refs/tags/$tag:refs/tags/$tag" \
      || die "the bundle of $tag from $from did not pass git's checks"
    resolved=$(clean --git-dir="$work/approved.git" rev-parse --verify --quiet "refs/tags/$tag^{commit}") || die "no tag $tag in $from"
    [[ $resolved == "$commit" ]] || die "the tag $tag is $resolved, not $commit: the deploy copy is made only of the commit you approved"
    if [[ -z $root ]]; then
      [[ $(stat -c '%u' "$uv") == 0 && ! -L $uv ]] && ! [[ $(stat -c '%A' "$uv") =~ ^.....w|^........w ]] \
        || die "$uv must be root's and writable by root only (it runs as root): install it from uv's official release (docs/runbooks/custody.md §2)"
    fi
    [[ -x $uv ]] || die "no uv at $uv (--uv)"
    [[ -x $(R /usr/bin/python3.12) ]] || die "the deploy copy needs /usr/bin/python3.12 (apt install python3.12-venv)"
    if [[ -e $rel ]]; then chmod -R u+w "$rel"; rm -rf "$rel"; fi  # an earlier build that did not finish
    mkdir -p "$rel"
    clean --git-dir="$work/approved.git" archive --format=tar "$commit" | tar -x -C "$rel" --no-same-owner
    rm -rf "$work"
    keep=()
    for name in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY; do
      [[ -z ${!name:-} ]] || keep+=("$name=${!name}")
    done
    (cd "$rel" && env -i PATH=/usr/bin:/bin HOME=/nonexistent "${keep[@]}" \
      UV_CACHE_DIR="$(R /var/cache/argus-build)" UV_PYTHON_DOWNLOADS=never UV_NO_CONFIG=1 \
      UV_PROJECT_ENVIRONMENT="$rel/.venv" \
      "$uv" sync --frozen --no-dev --compile-bytecode --python /usr/bin/python3.12) \
      || die "uv sync failed in $rel (run again: an unfinished release is rebuilt)"
    [[ -x $rel/.venv/bin/argus ]] || die "the virtualenv in $rel has no argus command"
    # ARGUS runs from the release's own src/ (it finds config/ and deploy/ beside it), compiled
    # now since the release becomes read-only; the local model's pinned certificate, named as
    # data/tls/local-llm.crt in config/llm.yaml, is the custody copy.
    if [[ -d $rel/src ]]; then
      env -i PATH=/usr/bin:/bin "$rel/.venv/bin/python" -I -m compileall -q "$rel/src" >/dev/null \
        || die "the release's source does not compile"
    fi
    mkdir -p "$rel/data/tls" && ln -sfn /etc/argus/tls/local-llm.crt "$rel/data/tls/local-llm.crt"
    printf 'tag=%s\ncommit=%s\nbuilt=%s\n' "$tag" "$commit" "$(date -u +%FT%TZ)" >"$rel/.argus-release"
    chown -R -h root:root "$rel"  # -h: a link itself, never what it points at
    chmod -R a-w "$rel"
    if [[ -n $(find "$rel" -perm /222 ! -type l -print -quit) ]]; then die "$rel still has a writable file"; fi
    did "the release $release_name: root's, read-only"
  fi
  if [[ -d $rel && $(readlink "$current" 2>/dev/null || true) != "releases/$release_name" ]]; then
    if (( check )); then todo "/opt/argus/current -> releases/$release_name"
    else
      ln -sfn "releases/$release_name" "$current.new" && mv -Tf "$current.new" "$current"
      did "/opt/argus/current -> releases/$release_name (services take it at their next restart)"
    fi
  elif [[ -d $rel ]]; then ok "/opt/argus/current -> releases/$release_name"
  fi
elif [[ -L $current && -d $current ]]; then
  ok "/opt/argus/current -> $(readlink "$current") (give --tag and --commit to deploy another)"
else
  todo "a deploy copy: run again with --tag <approved tag> --commit <its hash>"
fi
if [[ -d $current ]]; then
  bad=$(find -H "$current" -perm /222 ! -type l -print -quit 2>/dev/null || true)
  [[ -z $bad ]] || { if (( check )); then todo "the deploy copy is not read-only (e.g. $bad)"; else die "the deploy copy is not read-only (e.g. $bad)"; fi; }
fi

# ----------------------------------------------------------------------------- 4. secrets and files
say "credentials and files (from $from)"
python=$current/.venv/bin/python
if [[ -x $python ]]; then
  args=(-I -B -m argus.ops.custody import --checkout "$from" --etc "$(R /etc/argus)")
  (( check )) && args+=(--check)
  [[ -z $accept ]] || args+=(--accept-settings "$accept")
  rc=0; "$python" "${args[@]}" || rc=$?
  case $rc in
    0) ;;
    1) pending=$((pending + 1)) ;;
    3) pending=$((pending + 1)); warn "a credential every service needs is missing (above): add it to $from/.env or the file named, then run again" ;;
    *) die "the import failed (exit $rc)" ;;
  esac
  if (( ! check )); then
    for file in "$(R /etc/argus/credentials)"/*; do [[ -e $file ]] && chown root:root "$file"; done
    for file in argus.env data/asset_map.yaml; do [[ -e $(R /etc/argus/$file) ]] && chown root:$GROUP "$(R /etc/argus/$file)"; done
    for file in certs/siem-ca.crt tls/argus.crt tls/local-llm.crt; do [[ -e $(R /etc/argus/$file) ]] && chown root:root "$(R /etc/argus/$file)"; done
  fi
else
  todo "the credentials (the import runs from the deploy copy, which is not there yet)"
fi
for file in "$(R /etc/argus/credentials)"/*; do
  [[ -e $file ]] || continue
  name=${file##*/}
  if [[ -L $file || ! -f $file ]]; then todo "credential $name is not a regular file"; continue; fi
  mode=$(mode_of "$file") owner=$(owner_of "$file")
  [[ $mode == 600 || $mode == 400 ]] || todo "credential $name has mode $mode (wanted 600)"
  [[ $owner == - || $owner == root:root ]] || todo "credential $name is $owner's (wanted root:root)"
done

# ----------------------------------------------------------------------------- 5. units and wrapper
say "system units"
src=$current/deploy/custody/units
if [[ -d $src ]]; then
  for unit in "$src"/argus-*; do
    name=${unit##*/} dst=$(R "/etc/systemd/system/${unit##*/}")
    if [[ -f $dst ]] && cmp -s "$unit" "$dst"; then ok "$name"; continue; fi
    if (( check )); then todo "$name ($([[ -e $dst ]] && echo changed || echo new))"; continue; fi
    mkdir -p "${dst%/*}"
    tmp=$(mktemp "${dst%/*}/.$name.XXXXXX"); cp "$unit" "$tmp"; chmod 644 "$tmp"; chown root:root "$tmp"; mv -f "$tmp" "$dst"
    cmp -s "$unit" "$dst" || die "$name was not copied exactly"
    reload=1; did "$name (installed disabled)"
  done
  for dst in "$(R /etc/systemd/system)"/argus-*.service "$(R /etc/systemd/system)"/argus-*.timer; do
    [[ -e $dst && ! -e $src/${dst##*/} ]] && warn "${dst##*/} is installed but not in the release (left alone)"
  done
  wrapper=$(R /usr/local/sbin/argus-owner)
  if [[ -f $wrapper ]] && cmp -s "$current/deploy/custody/argus-owner" "$wrapper" && [[ $(mode_of "$wrapper") == 755 ]]; then
    ok "/usr/local/sbin/argus-owner"
  elif (( check )); then todo "/usr/local/sbin/argus-owner"
  else
    mkdir -p "${wrapper%/*}"
    tmp=$(mktemp "${wrapper%/*}/.argus-owner.XXXXXX"); cp "$current/deploy/custody/argus-owner" "$tmp"
    chmod 755 "$tmp"; chown root:root "$tmp"; mv -f "$tmp" "$wrapper"
    did "/usr/local/sbin/argus-owner"
  fi
else
  todo "the system units (from the deploy copy, which is not there yet)"
fi
if (( reload )); then
  if [[ -n $root ]]; then echo "   (fake root: systemctl daemon-reload not run)"
  else systemctl daemon-reload; did "systemd reloaded its units (nothing was started)"
  fi
fi

# ----------------------------------------------------------------------------- 6. the record
marker=$(R /etc/argus/custody.json)
if (( ! check )) && [[ -n $release_name && -d $current ]]; then
  if ! [[ -f $marker ]] || ! grep -q "\"commit\": \"$commit\"" "$marker"; then
    tmp=$(mktemp "$(R /etc/argus)/.custody.json.XXXXXX")
    printf '{"tag": "%s", "commit": "%s", "release": "%s", "installed_at": "%s"}\n' \
      "$tag" "$commit" "$release_name" "$(date -u +%FT%TZ)" >"$tmp"
    chmod 644 "$tmp"; chown root:root "$tmp"; mv -f "$tmp" "$marker"
    did "/etc/argus/custody.json ($tag): argus doctor now checks the custody layout"
  fi
elif [[ ! -f $marker ]]; then
  (( check )) && todo "/etc/argus/custody.json (written after a deploy)"
fi

# ----------------------------------------------------------------------------- 7. the operator
say "the operator's account${operator:+ ($operator)}"
if [[ -n $operator ]]; then
  for group in docker libvirt lxd incus-admin disk; do
    if member "$group" "$operator"; then
      warn "$operator is in the group $group: any process of that account (build tools, AI agents) can read every root-owned credential through it. Custody holds once it leaves: sudo gpasswd -d $operator $group (then sudo for docker)"
    fi
  done
  home_dir=$(awk -F: -v u="$operator" '$1 == u { print $6 }' "$(R /etc/passwd)" 2>/dev/null || true)
  if [[ -n $home_dir && -d $(R "$home_dir") ]] && (( 8#$(mode_of "$(R "$home_dir")") & 1 )); then
    warn "$home_dir may be entered by every account: chmod o-x $home_dir"
  fi
else
  warn "no operator account named (--operator, or run it through sudo)"
fi

# ----------------------------------------------------------------------------- summary
echo
if (( check )); then
  echo "install --check: $pending to do, $warnings warnings"
  (( pending == 0 )) && exit 0 || exit 1
fi
echo "install: done ($pending still to do, $warnings warnings)"
cat <<EOF

Next, the switch-over (production services stop and start: at a checkpoint):
  sudo argus-owner db upgrade                      # migration 0027: only the owner resumes a switch
  systemctl --user disable --now argus-collector argus-worker argus-assess argus-web argus-soak-sample.timer   # as ${operator:-the operator}
  sudo systemctl enable --now argus-collector argus-worker argus-assess argus-web argus-soak-sample.timer
  sudo argus-owner doctor                          # and \`uv run argus doctor\` as ${operator:-the operator}
Back to the shared layout: the same two systemctl lines the other way round.
EOF
(( pending == 0 )) || exit 1
