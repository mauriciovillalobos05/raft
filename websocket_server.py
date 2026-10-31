"""HTTPS KV gateway and authenticated, metadata-only operator telemetry."""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import time
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
import uvicorn
from inmem.kv_client import KVClient
from raft.raft_websocket_manager import WebSocketManager
from security.auth import get_auth
from security.http import COOKIE, require, check_origin, create_session, session_principal, revoke_session

CLUSTER_CONFIG = {
    "A": {"host": "127.0.0.1", "port": 5001},
    "B": {"host": "127.0.0.1", "port": 5002},
    "C": {"host": "127.0.0.1", "port": 5003},
}
ws_manager = WebSocketManager.get_ws_manager()


@asynccontextmanager
async def lifespan(app):
    auth = get_auth()  # Fail startup when credentials are missing or invalid.
    auth.web_tls()
    auth.server_context(auth.gateway_identity)
    ws_manager.set_event_loop(asyncio.get_running_loop())
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def secure_http(request: Request, call_next):
    if request.url.scheme != "https":
        return Response("HTTPS required", status_code=400)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


class KvItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    key: str = Field(min_length=1, max_length=65536)
    field: str = Field(min_length=1, max_length=65536)
    value: str = Field(max_length=65536)


@app.post("/auth/login")
def login(request: Request, response: Response, principal=Depends(require("ui", "operator"))):
    origin = request.headers.get("origin")
    if origin:
        check_origin(origin)
    response.set_cookie(COOKIE, create_session(principal), max_age=get_auth().session_ttl,
                        secure=True, httponly=True, samesite="strict", path="/")
    return {"role": principal.role, "expires_in": get_auth().session_ttl}


@app.post("/auth/logout")
def logout(request: Request, response: Response):
    check_origin(request.headers.get("origin"))
    token = request.cookies.get(COOKIE)
    if session_principal(token) is None:
        raise HTTPException(401, "Session required")
    revoke_session(token)
    response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict", path="/")
    return {"success": True}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.cookies.get(COOKIE)
    principal = session_principal(token)
    if (websocket.url.scheme != "wss" or not principal or principal.role not in {"ui", "operator"}
            or websocket.headers.get("origin") not in get_auth().origins):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    await ws_manager.add_client(websocket, authorized=lambda: session_principal(token) is not None)
    try:
        await ws_manager.on_client_connect(websocket)
        while True:
            if not session_principal(token):
                await websocket.close(code=1008)
                break
            try:
                # Telemetry sockets are receive-only from the browser's perspective.
                await asyncio.wait_for(websocket.receive_text(), timeout=1)
                await websocket.close(code=1008)
                break
            except asyncio.TimeoutError:
                continue
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await ws_manager.remove_client(websocket)


def kv_call(operation, **kwargs):
    client = KVClient(CLUSTER_CONFIG, identity=get_auth().gateway_identity)
    try:
        result = getattr(client, operation)(timestamp=int(time.time() * 1_000_000), **kwargs)
        if not result.get("success") and result.get("error") in {"CONNECTION_ERROR", "NO_LEADER", "MAX_RETRIES"}:
            raise HTTPException(503, "Cluster unavailable")
        return result
    finally:
        client.close()


@app.post("/kv-store")
def write_kv_store(item: KvItem, principal=Depends(require("client"))):
    return kv_call("set", **item.model_dump())


@app.get("/kv-store")
def read_kv_store(key: str, field: str, principal=Depends(require("client"))):
    return kv_call("get", key=key, field=field)


@app.delete("/kv-store")
def delete_kv_store(key: str, field: str, principal=Depends(require("client"))):
    return kv_call("delete", key=key, field=field)


@app.get("/health")
def health(principal=Depends(require("ui", "operator"))):
    return {"status": "ok", "websocket_clients": ws_manager.get_client_count()}


@app.get("/cluster/status")
def cluster_status(principal=Depends(require("ui", "operator"))):
    return {"node_ids": list(CLUSTER_CONFIG), "node_count": len(CLUSTER_CONFIG)}


def get_ws_manager():
    return ws_manager


# Same-origin assets contain no credentials or KV data. Build before starting.
ui_dist = Path(__file__).parent / "client" / "raft-visualization" / "dist"
if ui_dist.is_dir():
    app.mount("/", StaticFiles(directory=ui_dist, html=True), name="ui")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8765, ws="websockets-sansio", proxy_headers=False, **get_auth().web_tls())
