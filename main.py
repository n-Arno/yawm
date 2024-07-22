#!/usr/bin/env python3

import uvicorn
import asyncio
import time
import codecs
import os
import logging
from cachetools import TTLCache
from fastapi import FastAPI, Request, Response, Header
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from fastapi.responses import PlainTextResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Callable, Annotated
from contextlib import asynccontextmanager
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from jinja2 import Environment, DictLoader


_openapi = FastAPI.openapi


def openapi(self: FastAPI):
    _openapi(self)

    for _, method_item in self.openapi_schema.get("paths").items():
        for _, param in method_item.items():
            responses = param.get("responses")
            if "422" in responses:
                del responses["422"]

    self.openapi_schema["components"]["schemas"] = {}

    return self.openapi_schema


FastAPI.openapi = openapi

logger = logging.getLogger("uvicorn.error")

config_tmpl = """[Interface]
Address = {{ node.address }}
PrivateKey = {{ node.private }}
ListenPort = 52435
{% for peer in peers %}
[Peer]
Endpoint = {{ peer.ip }}
PublicKey = {{ peer.public }}
AllowedIPs = {{ peer.address }}
PersistentKeepalive = 25
{% endfor %}"""

env = Environment(loader=DictLoader({"config": config_tmpl}))
templates = Jinja2Templates(env=env)


def keys():
    private_key = X25519PrivateKey.generate()
    pubkey = private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    bytes_ = private_key.private_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()
    )

    prv = codecs.encode(bytes_, "base64").decode("utf8").strip()
    pub = codecs.encode(pubkey, "base64").decode("utf8").strip()

    return prv, pub


class CustomRoute(APIRoute):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lock = asyncio.Lock()

    def get_route_handler(self) -> Callable:
        original_route_handler = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            await self.lock.acquire()
            response: Response = await original_route_handler(request)
            self.lock.release()
            return response

        return custom_route_handler


@asynccontextmanager
async def lifespan(app: FastAPI):
    token = os.getenv("APP_TOKEN")
    if not token:
        token = "testing"
        logger.warning("APP_TOKEN is not set, using 'testing' as X-Auth-Token")
    app.state.token = token
    app.state.cache = TTLCache(maxsize=100, ttl=300)
    yield


description = """
**Yet Another Wireguard Mesh**

Using any generated `uuid` to identify a single mesh (max 100 at the same time), nodes can:
- `register` themselves (they will be identified by their source IP)
- `get` their own config (including all other registered nodes as peers)

All data (registered nodes and keys) expire after 5 minutes.

`X-Auth-Token` header for authentification is sourced from environment variable `APP_TOKEN`

**Use-case**

This tool can be used in a Cloud-Init script during a Terraform execution to:
- register nodes once they are up
- wait a minute or two for everyone
- get the config and install/start Wireguard
"""

app = FastAPI(lifespan=lifespan, title="yawm", description=description)
app.router.route_class = CustomRoute


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return PlainTextResponse(str(exc), status_code=400)


@app.get("/", response_class=PlainTextResponse, status_code=200)
async def health():
    return "OK"


@app.post("/{uuid}", response_class=PlainTextResponse, status_code=201)
async def register(request: Request, response: Response, uuid: str, x_auth_token: Annotated[str | None, Header()] = None):
    if not x_auth_token or x_auth_token != request.app.state.token:
        response.status_code = 401
        return "Not authenticated"
    source = request.client.host
    if uuid not in request.app.state.cache:
        request.app.state.cache[uuid] = {}
    if source not in request.app.state.cache[uuid]:
        prv, pub = keys()
        request.app.state.cache[uuid][source] = {"private": prv, "public": pub}
        return "Registered"
    response.status_code = 409
    return "Exists"


@app.get("/{uuid}", response_class=PlainTextResponse, status_code=200)
async def get(request: Request, response: Response, uuid: str, x_auth_token: Annotated[str | None, Header()] = None):
    if not x_auth_token or x_auth_token != request.app.state.token:
        response.status_code = 401
        return "Not authenticated"
    source = request.client.host
    if uuid in request.app.state.cache and source in request.app.state.cache[uuid]:
        orderedData = dict(sorted(request.app.state.cache[uuid].items()))
        members = list(orderedData.keys())
        node = {}
        peers = []
        for i in range(len(members)):
            if members[i] == source:
                node["address"] = f"10.0.0.{i+1}"
                node["private"] = orderedData[members[i]]["private"]
            else:
                peer = {}
                peer["address"] = f"10.0.0.{i+1}"
                peer["ip"] = members[i]
                peer["public"] = orderedData[members[i]]["public"]
                peers.append(peer)
        return templates.TemplateResponse(request=request, name="config", context={"node": node, "peers": peers})
    else:
        response.status_code = 404
        return "Not registered or expired"


if __name__ == "__main__":
    uvicorn.run(app="main:app", host="0.0.0.0", port=8080, reload=True, proxy_headers=True)
