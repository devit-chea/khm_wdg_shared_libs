#!/usr/bin/env python
from setuptools import setup, find_packages
import os
import re

# Read version from version.py
version_file = os.path.join(os.path.dirname(__file__), 'shared_libs', 'version.py')
with open(version_file, 'r') as f:
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", f.read(), re.M)
    if version_match:
        version = version_match.group(1)
    else:
        raise RuntimeError("Unable to find version string.")

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="django-shared-libs",
    version=version,
    author="Your Organization",
    author_email="dev@yourorg.com",
    description="Shared libraries and utilities for Django REST Framework projects",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/devit-chea/khm_wdg_shared_libs",
    project_urls={
        "Bug Tracker": "https://github.com/devit-chea/khm_wdg_shared_libs/issues",
        "Documentation": "https://django-shared-libs.readthedocs.io/",
    },
    packages=find_packages(exclude=["tests*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: Django",
        "Framework :: Django :: 3.2",
        "Framework :: Django :: 4.0",
        "Framework :: Django :: 4.1",
        "Framework :: Django :: 4.2",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-django>=4.5.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "isort>=5.10.0",
            "pre-commit>=2.20.0",
        ],
        "celery": [
            "celery>=5.2.0",
            "redis>=4.3.0",
        ],
        "metrics": [
            "prometheus-client>=0.14.0",
            "opentelemetry-api>=1.12.0",
            "opentelemetry-sdk>=1.12.0",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)