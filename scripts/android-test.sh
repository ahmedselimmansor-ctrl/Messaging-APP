#!/usr/bin/env bash
#
# Compiles and tests the Kotlin MTProto module without Gradle.
#
# Gradle would pull the Android toolchain and a large dependency graph for a
# module that is pure JVM. This path needs only a JDK and kotlinc, which is
# what makes the cross-implementation vectors cheap enough to run on every CI
# build rather than only on a developer's machine.
#
# Usage: ./scripts/android-test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/android"

command -v kotlinc >/dev/null || {
  echo "kotlinc is not on PATH." >&2
  echo "Install the Kotlin compiler, or run: ./gradlew :mtproto:test" >&2
  exit 1
}
command -v java >/dev/null || { echo "java is not on PATH." >&2; exit 1; }

LIB_DIR=".libs"
mkdir -p "$LIB_DIR" build

fetch() {
  local url="$1" file="$LIB_DIR/$(basename "$1")"
  [ -f "$file" ] || curl -sfL -o "$file" "$url"
  echo "$file"
}

KOTLIN_TEST=$(fetch "https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-test/2.1.0/kotlin-test-2.1.0.jar")
KOTLIN_TEST_JUNIT=$(fetch "https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-test-junit5/2.1.0/kotlin-test-junit5-2.1.0.jar")
JUNIT=$(fetch "https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.11.3/junit-platform-console-standalone-1.11.3.jar")

echo "--- compiling mtproto ---"
kotlinc mtproto/src/main/kotlin -d build/main.jar 2>&1 | grep -v '^warning: ' || true

echo "--- compiling tests ---"
kotlinc mtproto/src/test/kotlin \
  -cp "build/main.jar:$KOTLIN_TEST:$KOTLIN_TEST_JUNIT:$JUNIT" \
  -d build/test.jar 2>&1 | grep -v '^warning: ' || true

# kotlinc ships the stdlib next to itself; the compiled classes need it at run
# time and it is not on the JVM's default classpath.
KOTLIN_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v kotlinc)")")")"
STDLIB="$KOTLIN_HOME/lib/kotlin-stdlib.jar"
[ -f "$STDLIB" ] || { echo "cannot locate kotlin-stdlib.jar under $KOTLIN_HOME" >&2; exit 1; }

echo "--- running tests ---"
java -jar "$JUNIT" execute \
  --class-path "build/test.jar:build/main.jar:$STDLIB:$KOTLIN_TEST:$KOTLIN_TEST_JUNIT" \
  --scan-class-path=build/test.jar \
  --details=summary
