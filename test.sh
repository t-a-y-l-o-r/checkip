#!/usr/bin/env bash
coverage run -m pytest -rfs ./src/tests
coverage report --skip-covered -m
