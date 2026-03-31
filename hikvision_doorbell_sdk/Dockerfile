ARG BUILD_FROM
FROM ${BUILD_FROM}

ARG BUILD_ARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends libffi8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# SDK libraries (user must provide these before building)
COPY lib-${BUILD_ARCH}/ /usr/lib/hikvision/
ENV LD_LIBRARY_PATH=/usr/lib/hikvision

COPY src/ /app/

COPY rootfs/ /

RUN chmod a+x /run.sh

CMD ["/run.sh"]
