#!/usr/bin/env bash
coverage run -m pytest -rfs ./src
coverage report --skip-covered -m
