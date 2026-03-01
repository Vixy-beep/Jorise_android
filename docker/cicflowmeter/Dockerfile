# CICFlowMeter Docker Image
# ===========================
# Installs Java 8 + CICFlowMeter from source.
# Built by: docker compose -f docker-compose.lab.yml build

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-8-jre-headless wget unzip git \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Download CICFlowMeter release
RUN wget -q \
    https://github.com/ahlashkari/CICFlowMeter/releases/download/v4.0/CICFlowMeter-4.0.zip \
    -O /tmp/cfm.zip \
    && unzip -q /tmp/cfm.zip -d /opt/ \
    && rm /tmp/cfm.zip

# Make cfm executable
RUN chmod +x /opt/CICFlowMeter-4.0/bin/cfm

ENV PATH="/opt/CICFlowMeter-4.0/bin:$PATH"

WORKDIR /data
ENTRYPOINT ["cfm"]
CMD ["--help"]
