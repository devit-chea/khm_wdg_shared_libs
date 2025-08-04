# Django Shared Libs

A comprehensive, reusable shared libraries package for Django REST Framework microservices. This package provides common utilities, models, views, tasks, middleware, and more, to accelerate development and ensure consistency across multiple Django projects.

## Features

- Common utilities for date/time, security, and validation
- Custom exception handling and error codes
- Reusable serializers, model mixins, and view mixins
- Base tasks and task utilities for background processing
- Middleware for logging, metrics, and tracing
- Centralized settings and logging configuration
- Comprehensive test suite and documentation

## Installation

Install via pip (after building or publishing to your internal PyPI):

```bash
pip install django-shared-libs
```

Or add to your `requirements.txt`:

```
django-shared-libs
```

## Usage

Import and use the shared components in your Django microservices:

```python
from shared_libs.utils import common, datetime_utils
from shared_libs.schemas.base_serializers import BaseSerializer
from shared_libs.models.mixins import TimeStampedModel
from shared_libs.views.base_views import BaseAPIView
```

See the [docs/usage.txt](docs/usage.txt) directory for detailed usage examples.

## Project Structure

```text
django-shared-libs/
├── setup.py
├── setup.cfg
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── requirements.txt
├── requirements-dev.txt
├── Makefile
├── .gitignore
├── .pre-commit-config.yaml
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_utils/
│   │   ├── __init__.py
│   │   ├── test_common.py
│   │   ├── test_datetime_utils.py
│   │   └── test_security.py
│   ├── test_exceptions/
│   │   ├── __init__.py
│   │   └── test_handlers.py
│   ├── test_schemas/
│   │   ├── __init__.py
│   │   └── test_base_serializers.py
│   ├── test_models/
│   │   ├── __init__.py
│   │   └── test_mixins.py
│   ├── test_views/
│   │   ├── __init__.py
│   │   └── test_base_views.py
│   └── test_tasks/
│       ├── __init__.py
│       └── test_base_task.py
├── shared_libs/
│   ├── __init__.py
│   ├── version.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── common.py
│   │   ├── datetime_utils.py
│   │   ├── security.py
│   │   ├── validators.py
│   │   └── decorators.py
│   ├── exceptions/
│   │   ├── __init__.py
│   │   ├── handlers.py
│   │   ├── base.py
│   │   └── codes.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── base_serializers.py
│   │   ├── mixins.py
│   │   └── validators.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── mixins.py
│   │   ├── managers.py
│   │   └── fields.py
│   ├── views/
│   │   ├── __init__.py
│   │   ├── base_views.py
│   │   ├── mixins.py
│   │   └── permissions.py
│   ├── tasks/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   └── utils.py
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── logging.py
│   │   ├── metrics.py
│   │   └── tracing.py
│   └── settings/
│       ├── __init__.py
│       ├── base.py
│       └── logging.py
└── docs/
    ├── index.md
    ├── installation.md
    ├── usage/
    │   ├── utils.md
    │   ├── exceptions.md
    │   ├── schemas.md
    │   ├── models.md
    │   ├── views.md
    │   └── tasks.md
    └── examples/
        ├── basic_usage.py
        └── advanced_usage.py
```

## Contributing

1. Fork the repository and create your branch.
2. Write your code and tests.
3. Run the test suite with `make test`.
4. Submit a pull request.

## License

Distributed under the MIT License.

## Authors

- Your Team Name or Contributors