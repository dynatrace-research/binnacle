FROM python:slim AS builder
# FROM cgr.dev/chainguard/wolfi-base AS builder

# ensure both stages have same locations, to all the references in pip/python will work
ENV WD=/home/nonroot/app

ARG version=3.11
RUN useradd -ms /bin/bash nonroot

RUN apt update -y && apt install -y curl gcc

# install poetry
# configuration inspired by https://github.com/python-poetry/poetry/discussions/1879#discussioncomment-216865
ENV POETRY_HOME="/opt/poetry" \
    # do not ask any interactive question
    POETRY_NO_INTERACTION=1  \
    # make poetry create the virtual environment in the project's root it gets named `.venv`
    POETRY_VIRTUALENVS_IN_PROJECT=true
# prepend poetry and venv to path
ENV PATH="$POETRY_HOME/bin:$WORKDIR/.venv/bin:$PATH"
# install poetry - respects $POETRY_HOME & $POETRY_VERSION
RUN curl -sSL https://install.python-poetry.org | python -


USER nonroot
WORKDIR ${WD}

RUN pip install --upgrade pip

COPY --chown=nonroot:nonroot poetry.toml pyproject.toml README.md ./
COPY --chown=nonroot:nonroot binnacle ./binnacle

# ensure all venv files are copied, so they can be copied to new stage
# Poetry's venv didn't work, so use python's venv and disable poetry's
RUN python -m venv --copies ./venv

RUN poetry config virtualenvs.create false
RUN . ./venv/bin/activate && poetry install --no-cache --without dev


# ======================== final image ===============================
FROM python:slim 

ENV WD=/home/nonroot/app
# RUN adduser -D nonroot
RUN useradd -ms /bin/bash nonroot
USER nonroot
WORKDIR ${WD}

# 'activate' the virtual environment with all pre-installed dependencies
ENV PATH ${WD}/venv/bin:$PATH

COPY --from=builder --chown=nonroot:nonroot ${WD} ./
COPY --chown=nonroot:nonroot schema ./schema

EXPOSE 8000

ENTRYPOINT ["binnacle"]

# if no arguments are provided serve the API 
CMD ["serve"]