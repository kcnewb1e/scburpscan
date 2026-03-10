#!/bin/bash
set -e

if ! command -v javac &>/dev/null; then
    JAVAC_PATH=$(find /usr/lib/jvm -name "javac" 2>/dev/null | head -1)
    if [ -n "$JAVAC_PATH" ]; then
        export PATH="$(dirname "$JAVAC_PATH"):$PATH"
    else
        echo "ERROR: javac not found. Install JDK:"
        echo "  sudo apt install default-jdk"
        exit 1
    fi
fi

DEPS_DIR="libs"
OUT_DIR="build/classes"
JAR_OUT="build/libs/scburpscan.jar"

MONTOYA_JAR="montoya-api-2023.12.1.jar"
MONTOYA_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2023.12.1/montoya-api-2023.12.1.jar"

GSON_JAR="gson-2.10.1.jar"
GSON_URL="https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar"

mkdir -p "$DEPS_DIR" "$OUT_DIR" "build/libs"

echo "[1/4] Checking dependencies..."
[ -f "$DEPS_DIR/$MONTOYA_JAR" ] || curl -L -o "$DEPS_DIR/$MONTOYA_JAR" "$MONTOYA_URL"
[ -f "$DEPS_DIR/$GSON_JAR"    ] || curl -L -o "$DEPS_DIR/$GSON_JAR"    "$GSON_URL"
echo "      OK"

echo "[2/4] Compiling..."
find src/main/java -name "*.java" > /tmp/scburpscan_sources.txt
javac -cp "$DEPS_DIR/$MONTOYA_JAR:$DEPS_DIR/$GSON_JAR" \
      -d "$OUT_DIR" \
      --source-path src/main/java \
      @/tmp/scburpscan_sources.txt
echo "      OK"

echo "[3/4] Extracting Gson into classes (fat-jar)..."
cd "$OUT_DIR"
jar xf "../../$DEPS_DIR/$GSON_JAR"
cd - > /dev/null
echo "      OK"

echo "[4/4] Packaging JAR..."
jar cf "$JAR_OUT" -C "$OUT_DIR" .
echo "      OK"

echo ""
echo "Build complete: $JAR_OUT"
echo "Install: Burp Suite → Extensions → Add → Java → $JAR_OUT"
echo ""
echo "Features:"
echo "  Passive scan (always on): XSS reflection, SQLi errors, Open Redirect,"
echo "                            SSRF params, Sensitive info, Security headers"
echo "  Active scan  (toggle on): XSS fuzzing, SQLi error-based, Path traversal"
