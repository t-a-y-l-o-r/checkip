#!/usr/bin/env bash
coverage run -m pytest -rf ./src
coverage report --skip-covered -m
