.PHONY: format lint test all

format:
	black app tests
	isort app tests

lint:
	flake8 app tests

test:
	pytest

all: format lint test
