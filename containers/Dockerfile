# ---------------------------------------------------------------------------
# Supply-chain pinning
#
# Every third-party input below is pinned: the base image by digest, Go/npm/
# pip tools by exact version, release binaries by version + SHA-256, and git
# clones by commit SHA. To bump a tool, update its version AND checksum/commit
# together (e.g. `docker buildx imagetools inspect kalilinux/kali-rolling:latest`
# for the base image digest, the upstream release's checksums file for
# binaries, `git ls-remote <repo> HEAD` for clones).
#
# KALI_IMAGE may be overridden at build time with an internal mirror, but it
# must stay an `@sha256:` reference, e.g.:
#   docker build --build-arg KALI_IMAGE=registry.example.com/kali@sha256:... .
# ---------------------------------------------------------------------------
ARG KALI_IMAGE=kalilinux/kali-rolling:latest@sha256:02f5d6c019e549b0f55da58e835cad5355ef1030c6b2645265a324e37dfc4acc

# ---------------------------------------------------------------------------
# Builder stage: compile the Go tools here so the Go toolchain (~225MB) and the
# module/build caches never reach the runtime image. The resulting binaries are
# statically linked and copied into the final stage.
# ---------------------------------------------------------------------------
FROM ${KALI_IMAGE} AS gobuilder

RUN apt-get update && \
    apt-get install -y kali-archive-keyring && \
    apt-get update && \
    apt-get install -y --no-install-recommends golang-go git ca-certificates

# Exact module versions; go.sum verification against sum.golang.org applies.
ARG HTTPX_VERSION=v1.12.0
ARG KATANA_VERSION=v1.8.0
ARG VULNX_VERSION=v1.0.0
ARG GOSPIDER_VERSION=v1.1.6
ARG INTERACTSH_VERSION=v1.4.1
ARG GOVULNCHECK_VERSION=v1.9.0
ENV GOBIN=/out/bin
RUN mkdir -p /out/bin && \
    go install -v "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}" && \
    go install -v "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}" && \
    go install -v "github.com/projectdiscovery/cvemap/cmd/vulnx@${VULNX_VERSION}" && \
    go install -v "github.com/jaeles-project/gospider@${GOSPIDER_VERSION}" && \
    go install -v "github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_VERSION}" && \
    go install -v "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM ${KALI_IMAGE}

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

RUN apt-get update && \
    apt-get install -y kali-archive-keyring && \
    apt-get update && \
    apt-get upgrade -y

# No sudo: nothing the agent runs can become root. The one privileged step,
# /usr/local/sbin/strix-init, is run by the Strix host through the Docker API.
RUN useradd -m -s /bin/bash pentester && \
    touch /home/pentester/.hushlogin

RUN mkdir -p /home/pentester/tools /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    software-properties-common \
    gcc libc6-dev \
    python3 python3-pip python3-venv python3-setuptools \
    net-tools dnsutils whois \
    file xxd \
    jq parallel ripgrep grep \
    less procps htop \
    iproute2 iptables iputils-ping netcat-traditional \
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf \
    nodejs npm pipx \
    golang-go \
    libcap2-bin \
    gdb \
    libnss3-tools \
    chromium fonts-liberation


# Raw sockets for SYN scans only; NET_ADMIN stays with root (strix-init).
RUN setcap cap_net_raw,cap_net_bind_service+eip $(which nmap)

# The MITM CA is generated per container by strix-init, not baked into the
# image, so no two sandboxes (or anyone who pulls the image) share its key.

# uv: versioned release asset verified by SHA-256 (no `curl | sh`).
ARG UV_VERSION=0.13.1
ARG UV_SHA256_X86_64=eadd9d27c134ab5ac1ffd4473b97a741407f3ea238288f03121fc4deddf90220
ARG UV_SHA256_AARCH64=9041c73c99fdc5892cf128140beb354eca9231d502068cc36e6cb53a8e59ad14
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) UV_ARCH="x86_64"; UV_SHA256="${UV_SHA256_X86_64}" ;; \
        aarch64|arm64) UV_ARCH="aarch64"; UV_SHA256="${UV_SHA256_AARCH64}" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    test -n "${UV_SHA256}" || { echo "UV_SHA256 for ${UV_ARCH} is not set" >&2; exit 1; }; \
    curl -fsSL -o /tmp/uv.tar.gz \
        "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${UV_ARCH}-unknown-linux-gnu.tar.gz"; \
    echo "${UV_SHA256}  /tmp/uv.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/uv.tar.gz -C /tmp; \
    install -m 0755 "/tmp/uv-${UV_ARCH}-unknown-linux-gnu/uv" "/tmp/uv-${UV_ARCH}-unknown-linux-gnu/uvx" /usr/local/bin/; \
    rm -rf /tmp/uv.tar.gz "/tmp/uv-${UV_ARCH}-unknown-linux-gnu"

USER pentester
WORKDIR /tmp

# Go tools are built in the gobuilder stage; copy the static binaries only.
COPY --from=gobuilder --chown=pentester:pentester /out/bin/ /home/pentester/go/bin/

RUN nuclei -update-templates

RUN pipx install arjun==2.2.7 && \
    pipx install dirsearch==0.5.0 && \
    pipx inject dirsearch setuptools==80.10.2 && \
    pipx install wafw00f==2.4.2

ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global

RUN npm install -g retire@6.1.0 && \
    npm install -g eslint@10.12.0 && \
    npm install -g js-beautify@2.0.3 && \
    npm install -g @ast-grep/cli@0.51.0 && \
    npm install -g tree-sitter-cli@0.27.1 && \
    npm install -g agent-browser@0.26.0 && \
    npm cache clean --force && \
    # ast-grep ships two identical binaries (`ast-grep` and `sg`); dedupe (~52MB)
    ln -sf ast-grep /home/pentester/.npm-global/lib/node_modules/@ast-grep/cli/sg

ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
ENV AGENT_BROWSER_ARGS="--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US,--disable-background-networking,--disable-component-update,--disable-domain-reliability,--disable-sync,--metrics-recording-only,--no-pings"
ENV AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots
ENV AGENT_BROWSER_IDLE_TIMEOUT_MS=180000
USER root
RUN set -eu; \
    { \
        for var in AGENT_BROWSER_EXECUTABLE_PATH AGENT_BROWSER_USER_AGENT \
                   AGENT_BROWSER_ARGS AGENT_BROWSER_SCREENSHOT_DIR \
                   AGENT_BROWSER_IDLE_TIMEOUT_MS; do \
            eval "value=\${$var}"; \
            printf 'export %s="${%s:-%s}"\n' "$var" "$var" "$value"; \
        done; \
    } > /tmp/agent-browser.sh; \
    install -m 0644 /tmp/agent-browser.sh /etc/profile.d/agent-browser.sh; \
    rm /tmp/agent-browser.sh; \
    env -i bash -lc 'test "${AGENT_BROWSER_IDLE_TIMEOUT_MS}" = "180000"'
USER pentester
RUN /home/pentester/.npm-global/bin/agent-browser doctor --offline --quick

RUN set -eux; \
    TS_PARSER_DIR="/home/pentester/.tree-sitter/parsers"; \
    mkdir -p "${TS_PARSER_DIR}"; \
    # Grammars pinned to commit SHAs: "<owner>/<repo>@<commit>".
    for spec in \
        tree-sitter/tree-sitter-java@e10607b45ff745f5f876bfa3e94fbcc6b44bdc11 \
        tree-sitter/tree-sitter-javascript@58404d8cf191d69f2674a8fd507bd5776f46cb11 \
        tree-sitter/tree-sitter-python@26855eabccb19c6abf499fbc5b8dc7cc9ab8bc64 \
        tree-sitter/tree-sitter-go@2346a3ab1bb3857b48b29d779a1ef9799a248cd7 \
        tree-sitter/tree-sitter-bash@a06c2e4415e9bc0346c6b86d401879ffb44058f7 \
        tree-sitter/tree-sitter-json@254c42a6476413b776221e03982ac8ae159eeb72 \
        tree-sitter-grammars/tree-sitter-yaml@a1c4812a73ec5e089de8e441fdea3a921e8d5079 \
        tree-sitter/tree-sitter-typescript@75b3874edb2dc714fb1fd77a32013d0f8699989f; do \
        slug="${spec%@*}"; commit="${spec#*@}"; repo="${slug#*/}"; \
        dest="${TS_PARSER_DIR}/${repo}"; \
        if [ ! -d "${dest}" ]; then \
            git init -q "${dest}"; \
            git -C "${dest}" fetch -q --depth 1 "https://github.com/${slug}.git" "${commit}"; \
            git -C "${dest}" checkout -q --detach FETCH_HEAD; \
            test "$(git -C "${dest}" rev-parse HEAD)" = "${commit}"; \
        fi; \
    done; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" "${TS_PARSER_DIR}/tree-sitter-typescript-typescript"; \
    fi; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" "${TS_PARSER_DIR}/tree-sitter-typescript-tsx"; \
    fi; \
    tree-sitter init-config >/dev/null 2>&1 || true; \
    TS_CONFIG="/home/pentester/.config/tree-sitter/config.json"; \
    mkdir -p "$(dirname "${TS_CONFIG}")"; \
    [ -f "${TS_CONFIG}" ] || printf '{}\n' > "${TS_CONFIG}"; \
    TMP_CFG="$(mktemp)"; \
    jq --arg p "${TS_PARSER_DIR}" '.["parser-directories"] = ((.["parser-directories"] // []) + [$p] | unique)' "${TS_CONFIG}" > "${TMP_CFG}"; \
    mv "${TMP_CFG}" "${TS_CONFIG}"

WORKDIR /home/pentester/tools
# Third-party script repos pinned to reviewed commit SHAs ("<owner>/<repo>@<commit>").
RUN set -eux; \
    for spec in \
        aravind0x7/JS-Snooper@932704cbce1a04ebe89a558f395a6e474e01b15b \
        xchopath/jsniper.sh@65d0b508dc88e6de3dfe6ac60e6d89eca22be686 \
        ticarpi/jwt_tool@3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b; do \
        slug="${spec%@*}"; commit="${spec#*@}"; dest="${slug#*/}"; \
        git init -q "${dest}"; \
        git -C "${dest}" fetch -q --depth 1 "https://github.com/${slug}.git" "${commit}"; \
        git -C "${dest}" checkout -q --detach FETCH_HEAD; \
        test "$(git -C "${dest}" rev-parse HEAD)" = "${commit}"; \
    done; \
    chmod +x JS-Snooper/js_snooper.sh jsniper.sh/jsniper.sh jwt_tool/jwt_tool.py

USER root

# Release binaries: pinned version + per-architecture SHA-256 from the
# upstream release's checksums file. An empty checksum fails the build.
#
# trufflehog: installed root-owned and run through a wrapper that always passes
# `--no-update`. Runtime self-update is deliberately disabled: it would replace
# the binary with an unverified download inside the sandbox. Bump
# TRUFFLEHOG_VERSION (and its checksums) to pick up new detectors instead.
ARG TRUFFLEHOG_VERSION=3.95.9
ARG TRUFFLEHOG_SHA256_AMD64=f6d1106b85107d79527ed7a5b98b592beadd8b770dc3c9e8c1ad99e1b2cf127e
ARG TRUFFLEHOG_SHA256_ARM64=9d9c2ec4ea36a089a9c5aaafe1969d176013ddf9f44d68e8cd75291aed8c83ed
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) TH_ARCH="amd64"; TH_SHA256="${TRUFFLEHOG_SHA256_AMD64}" ;; \
        aarch64|arm64) TH_ARCH="arm64"; TH_SHA256="${TRUFFLEHOG_SHA256_ARM64}" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    test -n "${TH_SHA256}" || { echo "TRUFFLEHOG_SHA256 for ${TH_ARCH} is not set" >&2; exit 1; }; \
    mkdir -p /tmp/trufflehog; \
    curl -fsSL -o /tmp/trufflehog.tgz \
        "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TH_ARCH}.tar.gz"; \
    echo "${TH_SHA256}  /tmp/trufflehog.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trufflehog.tgz -C /tmp/trufflehog; \
    install -d -m 0755 /usr/local/libexec/trufflehog; \
    install -m 0755 /tmp/trufflehog/trufflehog /usr/local/libexec/trufflehog/trufflehog; \
    printf '%s\n' \
        '#!/bin/sh' \
        '# Self-update disabled: always run trufflehog with --no-update.' \
        'for arg in "$@"; do' \
        '    [ "$arg" = "--no-update" ] && exec /usr/local/libexec/trufflehog/trufflehog "$@"' \
        'done' \
        'exec /usr/local/libexec/trufflehog/trufflehog --no-update "$@"' \
        > /usr/local/bin/trufflehog; \
    chmod 0755 /usr/local/bin/trufflehog; \
    rm -rf /tmp/trufflehog /tmp/trufflehog.tgz; \
    trufflehog --version

# gitleaks: pinned release (no releases/latest lookup).
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_X64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) GITLEAKS_ARCH="x64"; GITLEAKS_SHA256="${GITLEAKS_SHA256_X64}" ;; \
        aarch64|arm64) GITLEAKS_ARCH="arm64"; GITLEAKS_SHA256="${GITLEAKS_SHA256_ARM64}" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    test -n "${GITLEAKS_SHA256}" || { echo "GITLEAKS_SHA256 for ${GITLEAKS_ARCH} is not set" >&2; exit 1; }; \
    mkdir -p /tmp/gitleaks; \
    curl -fsSL -o /tmp/gitleaks.tgz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tgz -C /tmp/gitleaks; \
    install -m 0755 /tmp/gitleaks/gitleaks /usr/local/bin/gitleaks; \
    rm -rf /tmp/gitleaks /tmp/gitleaks.tgz

# trivy: pinned release asset (no `curl | sh` from the main branch).
ARG TRIVY_VERSION=0.76.0
ARG TRIVY_SHA256_64BIT=e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7
ARG TRIVY_SHA256_ARM64=aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) TRIVY_ARCH="64bit"; TRIVY_SHA256="${TRIVY_SHA256_64BIT}" ;; \
        aarch64|arm64) TRIVY_ARCH="ARM64"; TRIVY_SHA256="${TRIVY_SHA256_ARM64}" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    test -n "${TRIVY_SHA256}" || { echo "TRIVY_SHA256 for ${TRIVY_ARCH} is not set" >&2; exit 1; }; \
    mkdir -p /tmp/trivy; \
    curl -fsSL -o /tmp/trivy.tgz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"; \
    echo "${TRIVY_SHA256}  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /tmp/trivy; \
    install -m 0755 /tmp/trivy/trivy /usr/local/bin/trivy; \
    rm -rf /tmp/trivy /tmp/trivy.tgz

RUN apt-get install -y wapiti

USER pentester

RUN pipx install semgrep==1.181.0 && \
    pipx install bandit==1.9.4

RUN npm install -g jshint@2.13.6

USER root

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    # Purge non-English locales (~160MB)
    find /usr/share/locale -mindepth 1 -maxdepth 1 -type d \
        ! -name 'en' ! -name 'en_US' ! -name 'C' -exec rm -rf {} + && \
    # Remove package documentation and man pages not needed at runtime (~95MB)
    rm -rf /usr/share/doc/* /usr/share/doc-base/* /usr/share/man/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

WORKDIR /app

# Caido CLI: pinned version verified by SHA-256.
# UNRESOLVED: fill in the SHA-256 of each caido-cli-v${CAIDO_VERSION}-linux-*.tar.gz
# (compute with `sha256sum` on a download you trust). The build fails closed
# while either value is empty; pass `--build-arg CAIDO_SHA256_X86_64=...` or
# commit the values here.
ARG CAIDO_VERSION=0.56.0
ARG CAIDO_SHA256_X86_64=
ARG CAIDO_SHA256_AARCH64=
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CAIDO_ARCH="x86_64"; CAIDO_SHA256="${CAIDO_SHA256_X86_64}"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        CAIDO_ARCH="aarch64"; CAIDO_SHA256="${CAIDO_SHA256_AARCH64}"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    if [ -z "${CAIDO_SHA256}" ]; then \
        echo "CAIDO_SHA256 for ${CAIDO_ARCH} is not set; refusing to install unverified caido-cli" >&2; exit 1; \
    fi && \
    wget -O caido-cli.tar.gz "https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz" && \
    echo "${CAIDO_SHA256}  caido-cli.tar.gz" | sha256sum -c - && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

USER pentester
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir caido-sdk-client==0.3.2 && \
    /app/.venv/bin/pip install --no-cache-dir \
        requests==2.34.2 httpx==0.28.1 beautifulsoup4==4.15.0 lxml==6.1.3 \
        pyjwt==2.15.1 cryptography==50.0.2 && \
    # jwt_tool's requirements.txt is unpinned; install its deps at exact versions.
    /app/.venv/bin/pip install --no-cache-dir \
        termcolor==3.3.0 cprint==1.2.2 pycryptodomex==3.24.1 ratelimit==2.2.1 && \
    printf '%s\n' \
        '#!/bin/bash' \
        'exec /app/.venv/bin/python /home/pentester/tools/jwt_tool/jwt_tool.py "$@"' \
        > /home/pentester/.local/bin/jwt_tool && \
    chmod +x /home/pentester/.local/bin/jwt_tool

COPY --chown=pentester:pentester strix/tools/proxy/caido_api.py /opt/strix-python/caido_api.py
ENV PYTHONPATH=/opt/strix-python

# Login shells (e.g. `bash -lc`) source /etc/profile, which on Debian/Kali
# hard-resets PATH and drops the image's ENV PATH entries. Re-add the same
# directories here — including /app/.venv/bin — so `python3`/`pip` resolve to
# the venv (which ships requests, httpx, bs4, lxml, pyjwt, cryptography, and the
# Caido SDK) instead of the externally-managed system interpreter.
RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY containers/strix-init.sh /usr/local/sbin/strix-init
RUN chown root:root /usr/local/bin/docker-entrypoint.sh /usr/local/sbin/strix-init && \
    chmod 755 /usr/local/bin/docker-entrypoint.sh /usr/local/sbin/strix-init && \
    # Strip setuid/setgid bits so no binary is a path back to root.
    find / -xdev -type f -perm /6000 -exec chmod ug-s {} + && \
    passwd -l root

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
