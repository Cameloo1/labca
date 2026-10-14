.PHONY: format lint test test-ui compile-requirements all

format:
	python -m black app tests alembic && python -m isort app tests alembic

lint:
	bash scripts/lint.sh

test:
	bash scripts/test.sh

test-ui:
	bash scripts/test-ui.sh

compile-requirements:
	bash scripts/compile-requirements.sh

all: format lint test
