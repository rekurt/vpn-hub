# A machine the integration suite can take over.
#
# Those tests build real interfaces, load a real ruleset and remove the default
# route along the way, so they need a host they may break -- which on a
# workstation means a container, and one with systemd as PID 1: the hub starts its
# listeners as transient units, and half of what the suite proves is what systemd
# reports back about them.
#
# The same sing-box release and checksum the hub installs, so what runs here is
# what runs on the hub. Go comes from the official image rather than a pinned
# tarball: one version to bump instead of one per architecture.
ARG GO_VERSION=1.26
FROM golang:${GO_VERSION} AS go

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# The same packages the integration job installs on its runner.
RUN apt-get update -qq \
	&& apt-get install -y -qq --no-install-recommends \
		systemd systemd-sysv dbus \
		iproute2 nftables iptables wireguard-tools \
		curl ca-certificates jq conntrack microsocks dnsmasq dnsutils \
		openvpn openssl procps iputils-ping python3 \
	&& rm -rf /var/lib/apt/lists/*

# The packaged resolver would hold port 53; the hub runs its own, in the
# namespaces they belong in.
RUN systemctl disable dnsmasq || true

COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:/root/go/bin:$PATH

# Pinned to the release the hub installs, and verified: an integration suite that
# proves REALITY works against some other build proves nothing about the hub.
ARG SINGBOX_VERSION=1.11.15
ARG SINGBOX_SHA256_amd64=950af37eb2d7e55dddae34a18411cd617303fd99d2dc75bc76b6dd9fcd97d9c5
ARG SINGBOX_SHA256_arm64=20a6a9cd259a95411599f811a5066513a98db63705a51121252ad27daf96c029
ARG TARGETARCH
RUN set -eu; \
	case "${TARGETARCH}" in \
		amd64) sha="${SINGBOX_SHA256_amd64}" ;; \
		arm64) sha="${SINGBOX_SHA256_arm64}" ;; \
		*) echo "no pinned checksum for ${TARGETARCH}" >&2; exit 1 ;; \
	esac; \
	archive="sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}.tar.gz"; \
	curl -fsSLO "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${archive}"; \
	echo "${sha}  ${archive}" | sha256sum -c -; \
	tar xzf "${archive}"; \
	install -m 0755 "sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}/sing-box" /usr/local/bin/sing-box; \
	rm -rf "${archive}" "sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}"; \
	sing-box version | head -1

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
