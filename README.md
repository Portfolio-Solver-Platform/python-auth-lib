# Auth Library for Python

A library that implements authentication and authorisation for services in the Portfolio Solver Platform (PSP).

## Installation

You can find [the package on PyPI](https://pypi.org/project/psp-auth/) and install it like you would any other PyPI package.

## Usage

The `Auth` class contains the core authentication and authorisation functionality. You create it like this:
```python
auth_core = Auth(AuthConfig("my-service"))
```
where `"my-service"` is the service name, corresponding with the resource in the auth provider.

> [!IMPORTANT]
> See [Keycloak](https://github.com/Portfolio-Solver-Platform/keycloak) for how to set up the resource.

### FastAPI

This section will describe how to use the FastAPI module. You initialise it like this:
```python
auth = FastAPIAuth(auth_core)
```

You should then use the `FastAPIAuth.add_docs` function on your FastAPI app:
```python
app = FastAPI(...)

auth.add_docs(app)
```

Then, for an endpoint, you can require that the request has scopes:
```python
SCOPES = ["my-scope"]
@app.get("/protected-route", dependencies=[auth.require_scopes(SCOPES)], openapi_extra=auth.scope_docs(SCOPES))
def protected_route():
    # (...)
```
Note that the `openapi_extra` part provides the OpenAPI documentation, while the `dependencies` part provides the functionality.

To get information about the user, you can use `auth.user()` in a `Depends`:
```python
@app.get("/protected-route")
def protected_route(user: Annotated[User, Depends(auth.user())]):
    # user has information like their ID, and optionally information like their name
    # (...)
```

Similarly, you can get access to the token using `Annotated[Token, Depends(auth.token())]`.
