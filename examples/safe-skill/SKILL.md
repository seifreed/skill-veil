# Python Development Environment Setup

A skill to help you set up a Python development environment with best practices.

## Description

This skill helps you configure a Python virtual environment with common development tools. It follows security best practices by using pinned versions and verified sources.

## Prerequisites

- Python 3.8 or higher installed
- pip package manager

## Setup

Create and activate a virtual environment:

```bash
# Create virtual environment
python3 -m venv .venv

# Activate on Linux/macOS
source .venv/bin/activate

# Activate on Windows
.venv\Scripts\activate
```

## Dependencies

Install dependencies with pinned versions from requirements.txt:

```bash
pip install -r requirements.txt
```

Example requirements.txt with pinned versions:

```
flask==2.3.3
requests==2.31.0
pytest==7.4.2
black==23.9.1
mypy==1.5.1
```

## Usage

Run the development server:

```python
from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello, World!"

if __name__ == "__main__":
    app.run(debug=True)
```

## Testing

Run tests with pytest:

```bash
pytest tests/ -v
```

## Code Formatting

Format code with black:

```bash
black src/
```

## Type Checking

Run mypy for type checking:

```bash
mypy src/
```

## Notes

- Always use virtual environments to isolate dependencies
- Pin dependency versions for reproducible builds
- Run tests before committing changes
