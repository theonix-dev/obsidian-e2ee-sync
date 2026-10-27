#!/usr/bin/env bash
#
# install.sh — bootstrap entry point for Obsidian E2EE Sync.
#
# Remote one-liner:
#   curl -fsSL https://raw.githubusercontent.com/<author>/<repo>/main/install.sh | bash
#   (with overrides:  curl -fsSL <url> | E2EE_REPO=owner/repo bash )
#
# Already-cloned checkout:
#   ./install.sh            (same as ./setup.sh)
#
# How mode detection works: when this file sits inside a complete repository
# checkout (server/, plugin/ and setup.sh next to it), it simply runs the
# interactive wizard from that checkout. Otherwise — which is exactly the
# situation after `curl | bash`, where the script only exists inside the pipe —
# it clones the full repository to a directory of your choice first, then runs
# the wizard from the clone (re-attaching your terminal for the questions).
#
# Environment overrides (all optional):
#   E2EE_REPO=<owner/repo>     GitHub repository to fetch         (default below)
#   E2EE_GIT_URL=<url>         full git clone URL                 (overrides REPO)
#   E2EE_TARBALL_URL=<url>     full tarball URL, no-.git fallback (overrides REPO)
#   E2EE_BRANCH=<name>         branch to fetch                    (default: main)

set -euo pipefail

# vvv EDIT THIS after you fork/push the repository vvv
GITHUB_REPO="${E2EE_REPO:-YOUR_USERNAME/obsidian-sync}"
# ^^^                                             ^^^

GIT_URL="${E2EE_GIT_URL:-https://github.com/${GITHUB_REPO}.git}"
BRANCH="${E2EE_BRANCH:-main}"
DEST_DEFAULT="${HOME:-$PWD}/obsidian-sync"

# ---------------------------------------------------------------- ui helpers
if [ -t 0 ] && [ -t 1 ]; then
  C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_B=$'\033[1m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
  C_G=''; C_Y=''; C_R=''; C_B=''; C_D=''; C_0=''
fi
say()  { printf '%s\n' "${C_B}==>${C_0} $*"; }
ok()   { printf '%s\n' " ${C_G}[ok]${C_0} $*"; }
warn() { printf '%s\n' " ${C_Y}[!]${C_0}  $*" >&2; }
die()  { printf '%s\n' " ${C_R}[x]${C_0}  $*" >&2; exit 1; }

# Prompt that works in every invocation shape: terminal, curl|bash (stdin is
# the script pipe -> read the real terminal instead). With NO terminal at all
# there is no safe place to read an answer from (stdin is the script stream
# itself), so the default is used with a warning. Empty answer = default.
prompt() {  # prompt QUESTION DEFAULT -> $REPLY
  local q="$1" def="$2" ans=""
  if [ -n "$def" ]; then
    printf '%s' "${C_B}${q}${C_0} ${C_D}[${def}]${C_0}: "
  else
    printf '%s' "${C_B}${q}${C_0}: "
  fi
  if [ -t 0 ]; then
    read -r ans || ans=""
  elif read -r ans 2>/dev/null </dev/tty; then
    : # got the answer from the controlling terminal
  else
    warn "No terminal available — using default '${def}'."
    ans=""
  fi
  REPLY="${ans:-$def}"
}

confirm() {  # confirm QUESTION [default y|n] -> 0 yes / 1 no
  local def="${2:-y}" ans
  while :; do
    prompt "$1 [y/n]" "$def"
    ans="$(printf '%s' "$REPLY" | tr '[:upper:]' '[:lower:]')"
    case "$ans" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *)     warn "Please answer y or n." ;;
    esac
  done
}

# ------------------------------------------------------------ mode detection
repo_root() {  # prints the checkout root if this file lives inside one
  local d
  d="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || return 1
  if [ -d "$d/server" ] && [ -d "$d/plugin" ] && [ -f "$d/setup.sh" ]; then
    printf '%s' "$d"
    return 0
  fi
  return 1
}

# ------------------------------------------------------------------- fetch --
fetch_tarball() {  # fetch_tarball DEST URL
  local dest="$1" url="$2"
  command -v curl >/dev/null 2>&1 \
    || die "'curl' not found — install git or curl, or clone the repo manually."
  command -v tar >/dev/null 2>&1 \
    || die "'tar' not found — install git, or clone the repo manually."
  mkdir -p "$dest"
  curl -fsSL "$url" | tar -xz --strip-components=1 -C "$dest"
}

clone_repo() {  # clone_repo DEST
  local dest="$1"
  if command -v git >/dev/null 2>&1; then
    if git clone -b "$BRANCH" "$GIT_URL" "$dest" 2>/dev/null \
       || git clone -b master "$GIT_URL" "$dest" 2>/dev/null \
       || git clone "$GIT_URL" "$dest" 2>/dev/null; then
      return 0
    fi
    warn "git clone failed — trying a tarball download instead."
  fi

  local urls=()
  if [ -n "${E2EE_TARBALL_URL:-}" ]; then
    urls=("$E2EE_TARBALL_URL")
  else
    local base="https://github.com/${GITHUB_REPO}/archive/refs/heads"
    urls=("$base/$BRANCH.tar.gz" "$base/master.tar.gz")
  fi
  local u
  for u in "${urls[@]}"; do
    fetch_tarball "$dest" "$u" && return 0
  done
  die "Could not download the repository ($GITHUB_REPO). Check the repo name / network."
}

bootstrap() {
  say "Running from a pipe — cloning the full repository first."

  local dest="" last=""
  while :; do
    prompt "Directory to clone into" "$DEST_DEFAULT"
    dest="${REPLY/#\~/${HOME:-$PWD}}"
    [ -n "$dest" ] || { warn "Path cannot be empty."; continue; }

    if [ -d "$dest/.git" ]; then
      if confirm "Already cloned here — pull updates (git pull --ff-only)" "y"; then
        git -C "$dest" pull --ff-only || warn "Pull failed — continuing with the existing copy."
      fi
      break
    fi

    if [ -e "$dest" ] && [ -n "$(ls -A "$dest" 2>/dev/null)" ]; then
      warn "'$dest' exists and is not empty (and not a git clone)."
      [ "$dest" = "$last" ] && die "Cannot use '$dest' — pick a different directory."
      last="$dest"
      continue
    fi
    break
  done

  if [ ! -f "$dest/setup.sh" ]; then
    clone_repo "$dest"
  fi
  [ -f "$dest/setup.sh" ] || die "Clone incomplete — setup.sh not found in '$dest'."

  ok "Repository ready: $dest"
  say "Starting the setup wizard…"
  RUN_WIZARD_FROM="$dest"
}

# ------------------------------------------------------------------- main --
if REPO_DIR="$(repo_root)"; then
  # Direct call from a downloaded/cloned repository.
  say "Local checkout detected — starting the setup wizard."
  exec "${BASH:-bash}" "$REPO_DIR/setup.sh" "$@"
fi

bootstrap

# curl|bash leaves stdin as the (already consumed) script pipe — hand the
# wizard a real terminal when one exists. Without a terminal the interactive
# wizard cannot run at all; print how to start it instead of feeding it
# script-stream garbage on stdin.
if [ -t 0 ]; then
  exec "${BASH:-bash}" "$RUN_WIZARD_FROM/setup.sh" "$@"
elif ( : 2>/dev/null </dev/tty ); then
  exec "${BASH:-bash}" "$RUN_WIZARD_FROM/setup.sh" "$@" < /dev/tty
else
  say "No terminal detected — the interactive wizard needs one. Start it yourself:"
  echo "      cd \"$RUN_WIZARD_FROM\" && ./setup.sh"
  echo "  (fully scripted installs are possible too:  printf 'answers…\\n' | ./setup.sh )"
  exit 0
fi
