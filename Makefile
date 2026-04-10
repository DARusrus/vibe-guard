install:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

clean:
	rm -rf __pycache__ .pytest_cache dist *.egg-info .coverage

build:
	python -m build

all: lint test build
