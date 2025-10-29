# Auth Library for Python

A library that implements the authentication and authorisation for services. It assumes that you use FastAPI.

## Installation

WIP

## Usage

First, create the auth:
```python
auth = Auth(AuthConfig("my-service"))
```
, where `"my-service"` is the service name, corresponding with the resource in the auth provider.

> [!IMPORTANT]
> See the [user service](https://github.com/Portfolio-Solver-Platform/user) for how to set up the resource.

Then, for an endpoint, you can require that the user has a role:
```python
@app.get("/protected-route")
@auth.require_role("my-role"):
def protected_route(request: Request):
    # (...)
```

> [!IMPORTANT]
> You NEED to have the `request: Request` parameter to the function.
> Additionally, `@auth.require_role(...)` has to be after `@app.get(...)`.

You can also require that the user has one out of a list of roles: `auth.require_any_role(["first-role", "second-role", ...])`
You can also require that the user has multiple roles: `auth.require_all_roles(["first-role", "second-role", ...])`

> [!NOTE]
> There are also similar decorators for checking roles on other resources than your own, for example: `auth.require_resource_role("other-service", "their-role")`.

If you need to access the user's information in an endpoint, you can do:
```python
def protected_route(request: Request):
    token = auth.get_token(request)
    user = token.user()
    # user has information, like `user.id()` and `user.full_name()`.
```

