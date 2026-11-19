#!/usr/bin/env sh
# grdctl prompts for the RDP username and password when they aren't given as
# arguments. Check that it reads them from stdin when stdin isn't a terminal,
# and that it fails cleanly when the input ends early.

set -e

grdctl=$1
schema_dir=$2

tmpdir=$(mktemp -d --tmpdir grdctl-test-XXXXXX)
trap 'rm -rf "$tmpdir"' EXIT

export HOME="$tmpdir/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_DATA_HOME="$HOME/.local/share"
export GSETTINGS_BACKEND=memory
export GSETTINGS_SCHEMA_DIR="$tmpdir/schemas"
mkdir -p "$HOME" "$GSETTINGS_SCHEMA_DIR"
cp "$schema_dir"/org.gnome.desktop.remote-desktop.*xml "$GSETTINGS_SCHEMA_DIR"
glib-compile-schemas "$GSETTINGS_SCHEMA_DIR"

printf 'alice\nsecret\n' | "$grdctl" --headless rdp set-credentials

status=$("$grdctl" --headless status --show-credentials)
echo "$status"
echo "$status" | grep -q 'Username: alice'
echo "$status" | grep -q 'Password: secret'

set +e
printf 'alice\n' | "$grdctl" --headless rdp set-credentials 2> "$tmpdir/stderr"
ret=$?
set -e
cat "$tmpdir/stderr"
if [ "$ret" -ne 1 ]; then
  echo "grdctl exited with $ret on early end of input, expected 1"
  exit 1
fi
