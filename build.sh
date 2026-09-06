#!/usr/bin/env bash
# Builds the whole project with nothing but `javac` and `jar` -- both part
# of any JDK (e.g. RHEL 8's `java-17-openjdk-devel` package). No Maven, no
# network access, no third-party jars: this project has zero dependencies
# by design (see the README/spec for why).
#
# Usage: ./build.sh
# Produces:
#   build/jars/agent.jar
#   build/jars/ca-service.jar
#   build/jars/file-receiver.jar

set -eu
set -o pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"

# Optional override for which JDK builds this project, e.g. on a RHEL 8 box
# where the `alternatives`-managed default `javac` isn't 17 -- see README
# "Using a non-default Java". Set JAVA_BIN yourself, or drop a java.env file
# next to this script containing JAVA_BIN=/path/to/java (same variable name
# as the systemd units' java.env, but this is a separate file: this one
# lives in the repo, theirs lives under ~/file-transfer). javac and jar are
# derived from JAVA_BIN's directory.
if [ -f "$ROOT/java.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/java.env"
  set +a
fi
if [ -n "${JAVA_BIN:-}" ]; then
  JDK_BINDIR="$(dirname "$JAVA_BIN")"
  JAVAC="$JDK_BINDIR/javac"
  JAR="$JDK_BINDIR/jar"
else
  JAVAC="javac"
  JAR="jar"
fi

rm -rf "$BUILD"
mkdir -p "$BUILD/classes/common" "$BUILD/jars"

compile() {
  local label="$1" srcdir="$2" outdir="$3" cp="${4:-}"
  echo "==> Compiling $label"
  mkdir -p "$outdir"
  local filelist
  filelist="$(mktemp)"
  find "$srcdir" -name '*.java' > "$filelist"
  if [ ! -s "$filelist" ]; then
    echo "No sources found under $srcdir" >&2
    exit 1
  fi
  # --release 17 pins the bytecode level so a build on a newer JDK still runs
  # on RHEL 8's Java 17; -encoding UTF-8 keeps the build independent of the
  # building machine's default charset, which is not UTF-8 everywhere.
  if [ -n "$cp" ]; then
    "$JAVAC" --release 17 -encoding UTF-8 -cp "$cp" -d "$outdir" @"$filelist"
  else
    "$JAVAC" --release 17 -encoding UTF-8 -d "$outdir" @"$filelist"
  fi
  rm -f "$filelist"
}

package_jar() {
  local name="$1" mainclass="$2" classesdir="$3" resdir="$4"
  echo "==> Packaging $name.jar"
  local stage="$BUILD/stage-$name"
  rm -rf "$stage"
  mkdir -p "$stage"
  cp -r "$BUILD/classes/common/." "$stage/"
  cp -r "$classesdir/." "$stage/"
  if [ -d "$resdir" ]; then
    cp -r "$resdir/." "$stage/"
  fi
  local manifest
  manifest="$(mktemp)"
  printf 'Main-Class: %s\n' "$mainclass" > "$manifest"
  "$JAR" --create --file "$BUILD/jars/$name.jar" --manifest "$manifest" -C "$stage" .
  rm -f "$manifest"
  rm -rf "$stage"
}

compile common "$ROOT/common/src/main/java" "$BUILD/classes/common"

compile agent "$ROOT/agent/src/main/java" "$BUILD/classes/agent" "$BUILD/classes/common"
compile ca-service "$ROOT/server/ca-service/src/main/java" "$BUILD/classes/ca-service" "$BUILD/classes/common"
compile file-receiver "$ROOT/server/file-receiver/src/main/java" "$BUILD/classes/file-receiver" "$BUILD/classes/common"

package_jar agent com.filetransfer.agent.Main \
  "$BUILD/classes/agent" "$ROOT/agent/src/main/resources"
package_jar ca-service com.filetransfer.ca.CaServiceMain \
  "$BUILD/classes/ca-service" "$ROOT/server/ca-service/src/main/resources"
package_jar file-receiver com.filetransfer.receiver.ReceiverMain \
  "$BUILD/classes/file-receiver" "$ROOT/server/file-receiver/src/main/resources"

echo
echo "==> Done. Jars in $BUILD/jars/:"
ls -la "$BUILD/jars/"
