FROM --platform=linux/amd64 python:3.11-slim@sha256:66e41d125c90d679ad69b264ac7b78a3bd27e7510b63ba5987ad42678bbefc32

RUN apt-get update && apt-get install -y gcc libssl-dev

RUN adduser --disabled-password dragonfly
USER dragonfly

ENV PATH="${PATH}:/home/dragonfly/.local/bin"

# Set Git SHA environment variable
ARG git_sha="development"
ENV GIT_SHA=$git_sha

WORKDIR /app
COPY pyproject.toml src ./
RUN python -m pip install .

EXPOSE 8080

CMD ["uvicorn", "dragonfly.server:app", "--host", "0.0.0.0", "--port", "8080"]
