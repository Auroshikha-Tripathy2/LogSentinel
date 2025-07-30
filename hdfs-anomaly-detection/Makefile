.PHONY: help install test clean build docker-build docker-run lint format docs

# Default target
help:
	@echo "HDFS Anomaly Detection System - Available Commands:"
	@echo ""
	@echo "Installation:"
	@echo "  install     - Install dependencies"
	@echo "  install-dev - Install development dependencies"
	@echo ""
	@echo "Development:"
	@echo "  test        - Run tests"
	@echo "  lint        - Run linting (flake8)"
	@echo "  format      - Format code (black)"
	@echo "  docs        - Generate documentation"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  docker-clean - Clean Docker images"
	@echo ""
	@echo "Project:"
	@echo "  run         - Run anomaly detection"
	@echo "  run-plot    - Run with plot generation"
	@echo "  clean       - Clean generated files"
	@echo "  build       - Build package"

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install pytest black flake8 sphinx sphinx-rtd-theme

# Development
test:
	pytest tests/ -v

lint:
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

format:
	black .

docs:
	sphinx-build -b html docs/ docs/_build/html

# Docker
docker-build:
	docker build -t hdfs-anomaly-detector .

docker-run:
	docker run -v $(PWD)/data:/app/data -v $(PWD)/plots:/app/plots hdfs-anomaly-detector

docker-clean:
	docker rmi hdfs-anomaly-detector || true

# Project
run:
	python enterprise_detector.py

run-plot:
	python enterprise_detector.py --plot

clean:
	rm -rf __pycache__/
	rm -rf *.pyc
	rm -rf plots/*.png
	rm -rf models/*.pkl
	rm -rf configs/*.json
	rm -rf logs/*.log
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/

build:
	python setup.py sdist bdist_wheel

# Docker Compose
compose-up:
	docker-compose up --build

compose-down:
	docker-compose down

compose-logs:
	docker-compose logs -f

# Verification
verify-data:
	python verify_labels.py

parse-logs:
	python hdfs_parser.py

# Quick start
quick-start: install run-plot

# Development workflow
dev-setup: install-dev format lint test

# Production setup
prod-setup: docker-build docker-run 