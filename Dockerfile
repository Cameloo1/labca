FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS css
ADD --checksum=sha256:4af3198c015616ea7d6617974ec3d70d987ecc00c1ca8463b0a30fd65cc7c06e --chmod=755 https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.19/tailwindcss-linux-x64 /usr/local/bin/tailwindcss
WORKDIR /build
COPY tailwind.config.js ./
COPY app/ ./app/
RUN mkdir -p /out && tailwindcss -c tailwind.config.js -i app/static/src/input.css -o /out/app.css --minify

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS builder
RUN python -m venv /opt/venv
COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
    && /opt/venv/bin/python -m compileall -q /opt/venv

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS final
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 labca \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin labca
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app/ /app/app/
COPY alembic/ /app/alembic/
COPY alembic.ini /app/alembic.ini
COPY --chmod=0755 docker-entrypoint.sh /app/docker-entrypoint.sh
COPY --from=css /out/app.css /app/app/static/css/app.css
RUN python -m compileall -q /app/app /app/alembic \
    && mkdir -p /data && chown 10001:10001 /data && chmod 0700 /data
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["serve"]
