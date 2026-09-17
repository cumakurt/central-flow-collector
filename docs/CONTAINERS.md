# Containers

`deploy/docker/Dockerfile` builds a static non-root image. `deploy/docker/docker-compose.yml` provides a ClickHouse + collector development/POC stack. Change the example ClickHouse password before use.

A Kubernetes/Helm deployment is available under `deploy/helm/central-flow-collector`. Provide production secrets with Kubernetes Secret/external secret tooling rather than embedding them in `values.yaml`.
