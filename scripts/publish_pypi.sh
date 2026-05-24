#!/bin/bash
# StrixPro PyPI 发布脚本
# 使用: ./scripts/publish_pypi.sh
# 需要先配置 PyPI token: export TWINE_PASSWORD=your_token

set -e
cd "$(dirname "$0")/.."

# Clean old builds
rm -rf dist/ build/ *.egg-info

# Build
python -m build

# Check
twine check dist/*

# Upload
echo "Uploading to PyPI..."
twine upload dist/*
echo "Published!"
