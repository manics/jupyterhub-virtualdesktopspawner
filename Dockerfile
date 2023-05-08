FROM docker.io/jupyterhub/k8s-hub:2.0.0

USER root

COPY virtualdesktopspawner /src/jupyterhub-virtualdesktopspawner/virtualdesktopspawner
COPY pyproject.toml requirements.txt LICENSE README.md /src/jupyterhub-virtualdesktopspawner/

ARG SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0
RUN pip install /src/jupyterhub-virtualdesktopspawner/

USER ${NB_USER}
