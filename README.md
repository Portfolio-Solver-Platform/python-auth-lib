# Auth Library for Python

A library that implements the authentication and authorisation for services. It assumes that you use FastAPI.

## Installation

WIP

## Usage

First, when you have created your FastAPI `app`, you need to enable the authentication:
```python
# (...)

app = FastAPI(...)

auth = Auth()
auth.enable(app, "secret-string")

# (...)
```

> [!WARNING]
> The `"secret-string"` should be secret.

> [!IMPORTANT]
> Also, it may be necessary to move `auth = Auth()` into a different file to avoid circular imports, depending on your file structure.

Then, for an endpoint, you can require that the user has a role:
```python
@app.get("/protected-route")
@auth.require_role("my-service", "my-role"):
def protected_route(request: Request):
  # (...)
```

> [!IMPORTANT]
> You NEED to have the `request: Request` parameter to the function.
> Additionally, `@auth.require_role(...)` has to be after `@app.get(...)`.

## Contributing

Download the development dependencies by using `pip install -r requirements-dev.txt`.

### Updating dependencies
You can manually update dependencies by:
```bash
pip-compile pyproject.toml -o requirements.txt --strip-extras
pip-compile pyproject.toml --extra dev -o requirements-dev.txt --strip-extras
```
