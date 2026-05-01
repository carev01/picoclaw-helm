import asyncio
import base64
import json
import os
import re
import secrets
import signal
import time
from collections import deque
from pathlib import Path

from starlette.applications import Starlette
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
)
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
SECRET_FIELDS = {
    "api_key", "token", "app_secret", "encrypt_key",
    "verification_token", "bot_token", "app_token",
    "channel_secret", "channel_access_token", "client_secret",
    "corp_secret", "access_token", "session_store_path",
    "webhook_url", "encoding_aes_key", "client_id", "corp_id",
    "device_id", "homeserver", "nickserv_password", "sasl_password",
    "password", "real_name", "sasl_user", "user",
    "GITHUB_PERSONAL_ACCESS_TOKEN", "BRAVE_API_KEY", "CONTEXT7_API_KEY",
    "SLACK_BOT_TOKEN", "SLACK_TEAM_ID", "auth_token", "secret",
    "crypto_passphrase",
}

CONFIG_DIR = Path(os.environ.get("PICOCLAW_HOME", Path.home() / ".picoclaw"))
CONFIG_PATH = CONFIG_DIR / "config.json"

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(16)
    print(f"Generated admin password: {ADMIN_PASSWORD}")


class BasicAuthBackend(AuthenticationBackend):
    async def authenticate(self, conn):
        if "Authorization" not in conn.headers:
            return None

        auth = conn.headers["Authorization"]
        try:
            scheme, credentials = auth.split()
            if scheme.lower() != "basic":
                return None
            decoded = base64.b64decode(credentials).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            raise AuthenticationError("Invalid credentials")

        username, _, password = decoded.partition(":")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            return AuthCredentials(["authenticated"]), SimpleUser(username)

        raise AuthenticationError("Invalid credentials")


def require_auth(request: Request):
    if not request.user.is_authenticated:
        return PlainTextResponse(
            "Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="picoclaw"'},
        )
    return None


def load_config():
    if not CONFIG_PATH.exists():
        return default_config()
    try:
        return json.loads(CONFIG_PATH.read_text())
    except Exception:
        return default_config()


def save_config(data):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=2))


def default_config():
    return {
        "agents": {
            "defaults": {
                "workspace": "~/.picoclaw/workspace",
                "restrict_to_workspace": True,
                "model_name": "gpt-5.4",
                "max_tokens": 8192,
                "context_window": 131072,
                "temperature": 0.7,
                "max_tool_iterations": 20,
                "summarize_message_threshold": 20,
                "summarize_token_percent": 75,
                "split_on_marker": False,
                "tool_feedback": {
                    "enabled": False,
                    "max_args_length": 300,
                    "separate_messages": False
                }
            }
        },
        "model_list": [
            {
                "model_name": "gpt-5.4",
                "model": "openai/gpt-5.4",
                "api_key": "",
                "api_base": "https://api.openai.com/v1"
            },
            {
                "model_name": "claude-sonnet-4.6",
                "model": "anthropic/claude-sonnet-4.6",
                "api_key": "",
                "api_base": "https://api.anthropic.com/v1",
                "thinking_level": "high"
            },
            {
                "model_name": "deepseek",
                "model": "deepseek/deepseek-chat",
                "api_key": ""
            },
            {
                "model_name": "gemini",
                "model": "antigravity/gemini-2.0-flash",
                "auth_method": ""
            },
            {
                "model_name": "lmstudio-local",
                "model": "lmstudio/openai/gpt-oss-20b"
            }
        ],
        "channels": {
            "telegram": {"enabled": False, "token": "", "base_url": "", "proxy": "", "allow_from": [], "reasoning_channel_id": "", "use_markdown_v2": False, "streaming": {"enabled": True}},
            "discord": {"enabled": False, "token": "", "proxy": "", "allow_from": [], "group_trigger": {"mention_only": False}, "reasoning_channel_id": ""},
            "slack": {"enabled": False, "bot_token": "", "app_token": "", "allow_from": [], "reasoning_channel_id": ""},
            "whatsapp": {"enabled": False, "bridge_url": "ws://localhost:3001", "use_native": False, "session_store_path": "", "allow_from": [], "reasoning_channel_id": ""},
            "feishu": {"enabled": False, "app_id": "", "app_secret": "", "encrypt_key": "", "verification_token": "", "allow_from": [], "reasoning_channel_id": "", "random_reaction_emoji": [], "is_lark": False, "placeholder": {"enabled": True, "text": ["Thinking...", "Processing...", "Typing..."]}},
            "dingtalk": {"enabled": False, "client_id": "", "client_secret": "", "allow_from": [], "reasoning_channel_id": ""},
            "qq": {"enabled": False, "app_id": "", "app_secret": "", "allow_from": [], "reasoning_channel_id": ""},
            "line": {"enabled": False, "channel_secret": "", "channel_access_token": "", "webhook_path": "/webhook/line", "allow_from": [], "reasoning_channel_id": ""},
            "maixcam": {"enabled": False, "host": "0.0.0.0", "port": 18790, "allow_from": [], "reasoning_channel_id": ""},
            "onebot": {"enabled": False, "ws_url": "ws://127.0.0.1:3001", "access_token": "", "reconnect_interval": 5, "group_trigger_prefix": [], "allow_from": [], "reasoning_channel_id": ""},
            "wecom": {"enabled": False, "bot_id": "", "secret": "", "websocket_url": "wss://openws.work.weixin.qq.com", "send_thinking_message": True, "allow_from": [], "reasoning_channel_id": ""},
            "matrix": {"enabled": False, "homeserver": "https://matrix.org", "user_id": "", "access_token": "", "device_id": "", "join_on_invite": True, "allow_from": [], "group_trigger": {"mention_only": True}, "placeholder": {"enabled": True, "text": "Thinking... \ud83d\udcad"}, "reasoning_channel_id": "", "crypto_database_path": "", "crypto_passphrase": ""},
            "irc": {"enabled": False, "server": "irc.libera.chat:6697", "tls": True, "nick": "mybot", "user": "", "real_name": "", "password": "", "nickserv_password": "", "sasl_user": "", "sasl_password": "", "channels": ["#mychannel"], "request_caps": ["server-time", "message-tags"], "allow_from": [], "group_trigger": {"mention_only": True}, "typing": {"enabled": False}, "reasoning_channel_id": ""},
            "pico": {"enabled": False, "token": "", "allow_token_query": False, "allow_origins": [], "ping_interval": 30, "read_timeout": 60, "max_connections": 100, "allow_from": []},
            "pico_client": {"enabled": False, "url": "wss://remote-pico-server/pico/ws", "token": "", "session_id": "", "ping_interval": 30, "read_timeout": 60, "allow_from": []}
        },
        "providers": {
            "anthropic": {"api_key": "", "api_base": ""},
            "openai": {"api_key": "", "api_base": "", "web_search": True},
            "openrouter": {"api_key": "", "api_base": ""},
            "groq": {"api_key": "", "api_base": ""},
            "zhipu": {"api_key": "", "api_base": ""},
            "gemini": {"api_key": "", "api_base": ""},
            "vllm": {"api_key": "", "api_base": ""},
            "nvidia": {"api_key": "", "api_base": "", "proxy": ""},
            "moonshot": {"api_key": "", "api_base": ""},
            "ollama": {"api_key": "", "api_base": "http://localhost:11434/v1"},
            "cerebras": {"api_key": "", "api_base": ""},
            "volcengine": {"api_key": "", "api_base": ""},
            "mistral": {"api_key": "", "api_base": "https://api.mistral.ai/v1"},
            "qwen": {"api_key": "", "api_base": ""},
            "avian": {"api_key": "", "api_base": "https://api.avian.io/v1"},
            "longcat": {"api_key": "", "api_base": "https://api.longcat.chat/openai"}
        },
        "gateway": {"host": "127.0.0.1", "port": 18790, "hot_reload": False, "log_level": "fatal"},
        "tools": {
            "allow_read_paths": None,
            "allow_write_paths": None,
            "web": {
                "enabled": True,
                "prefer_native": True,
                "fetch_limit_bytes": 10485760,
                "format": "plaintext",
                "provider": "auto",
                "private_host_whitelist": [],
                "brave": {"enabled": False, "api_key": "", "api_keys": [], "max_results": 5},
                "tavily": {"enabled": False, "api_key": "", "base_url": "", "max_results": 0},
                "sogou": {"enabled": True, "max_results": 5},
                "duckduckgo": {"enabled": False, "max_results": 5},
                "perplexity": {"enabled": False, "api_key": "", "api_keys": [], "max_results": 5},
                "searxng": {"enabled": False, "base_url": "http://localhost:8888", "max_results": 5},
                "glm_search": {"enabled": False, "api_key": "", "base_url": "https://open.bigmodel.cn/api/paas/v4/web_search", "search_engine": "search_std", "max_results": 5},
                "baidu_search": {"enabled": False, "api_key": "", "base_url": "https://qianfan.baidubce.com/v2/ai_search/web_search", "max_results": 10}
            },
            "cron": {"enabled": True, "exec_timeout_minutes": 5},
            "exec": {"enabled": True, "enable_deny_patterns": True, "custom_deny_patterns": None, "custom_allow_patterns": None},
            "skills": {
                "enabled": True,
                "github": {"base_url": "https://github.com", "proxy": "", "token": ""},
                "max_concurrent_searches": 2,
                "search_cache": {"max_size": 50, "ttl_seconds": 300},
                "registries": {
                    "clawhub": {
                        "enabled": True,
                        "base_url": "https://clawhub.ai",
                        "auth_token": "",
                        "search_path": "/api/v1/search",
                        "skills_path": "/api/v1/skills",
                        "download_path": "/api/v1/download",
                        "timeout": 0,
                        "max_zip_size": 0,
                        "max_response_size": 0
                    },
                    "github": {
                        "enabled": True,
                        "base_url": "https://github.com",
                        "proxy": "",
                        "auth_token": ""
                    }
                }
            },
            "media_cleanup": {"enabled": True, "max_age_minutes": 30, "interval_minutes": 5},
            "mcp": {
                "enabled": False,
                "discovery": {
                    "enabled": False,
                    "ttl": 5,
                    "max_search_results": 5,
                    "use_bm25": True,
                    "use_regex": False
                },
                "servers": {
                    "context7": {
                        "enabled": False,
                        "type": "http",
                        "url": "https://mcp.context7.com/mcp",
                        "headers": {"CONTEXT7_API_KEY": ""}
                    },
                    "filesystem": {
                        "enabled": False,
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                    },
                    "github": {
                        "enabled": False,
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": ""}
                    },
                    "brave-search": {
                        "enabled": False,
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-brave-search"],
                        "env": {"BRAVE_API_KEY": ""}
                    },
                    "postgres": {
                        "enabled": False,
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://user:password@localhost/dbname"]
                    },
                    "slack": {
                        "enabled": False,
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-slack"],
                        "env": {"SLACK_BOT_TOKEN": "", "SLACK_TEAM_ID": ""}
                    }
                }
            },
            "append_file": {"enabled": True},
            "edit_file": {"enabled": True},
            "find_skills": {"enabled": True},
            "i2c": {"enabled": False},
            "install_skill": {"enabled": True},
            "list_dir": {"enabled": True},
            "message": {"enabled": True},
            "read_file": {"enabled": True, "mode": "bytes"},
            "send_tts": {"enabled": False},
            "serial": {"enabled": False},
            "spawn": {"enabled": True},
            "spi": {"enabled": False},
            "subagent": {"enabled": True},
            "web_fetch": {"enabled": True},
            "write_file": {"enabled": True}
        },
        "heartbeat": {"enabled": True, "interval": 30},
        "devices": {"enabled": False, "monitor_usb": True},
        "voice": {"model_name": "", "echo_transcription": False},
        "hooks": {"enabled": True, "defaults": {"observer_timeout_ms": 500, "interceptor_timeout_ms": 5000, "approval_timeout_ms": 60000}}
    }


def mask_secrets(data, _path=""):
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if k in SECRET_FIELDS and isinstance(v, str) and v:
                result[k] = v[:8] + "***" if len(v) > 8 else "***"
            else:
                result[k] = mask_secrets(v, f"{_path}.{k}")
        return result
    if isinstance(data, list):
        return [mask_secrets(item, _path) for item in data]
    return data


def merge_secrets(new_data, existing_data):
    if isinstance(new_data, dict) and isinstance(existing_data, dict):
        result = {}
        for k, v in new_data.items():
            if k in SECRET_FIELDS and isinstance(v, str) and (v.endswith("**") or v == ""):
                result[k] = existing_data.get(k, "")
            else:
                result[k] = merge_secrets(v, existing_data.get(k, {}))
        return result
    return new_data


class GatewayManager:
    def __init__(self):
        self.process: asyncio.subprocess.Process | None = None
        self.state = "stopped"
        self.logs: deque[str] = deque(maxlen=500)
        self.start_time: float | None = None
        self.restart_count = 0
        self._read_tasks: list[asyncio.Task] = []

    async def start(self):
        if self.process and self.process.returncode is None:
            return
        self.state = "starting"
        try:
            self.process = await asyncio.create_subprocess_exec(
                "picoclaw", "gateway",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            self.state = "running"
            self.start_time = time.time()
            task = asyncio.create_task(self._read_output())
            self._read_tasks.append(task)
        except Exception as e:
            self.state = "error"
            self.logs.append(f"Failed to start gateway: {e}")

    async def stop(self):
        if not self.process or self.process.returncode is not None:
            self.state = "stopped"
            return
        self.state = "stopping"
        self.process.terminate()
        try:
            await asyncio.wait_for(self.process.wait(), timeout=10)
        except asyncio.TimeoutError:
            self.process.kill()
            await self.process.wait()
        self.state = "stopped"
        self.start_time = None

    async def restart(self):
        await self.stop()
        self.restart_count += 1
        await self.start()

    async def _read_output(self):
        try:
            while self.process and self.process.stdout:
                line = await self.process.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                cleaned = ANSI_ESCAPE.sub("", decoded)
                self.logs.append(cleaned)
        except asyncio.CancelledError:
            return
        if self.process and self.process.returncode is not None and self.state == "running":
            self.state = "error"
            self.logs.append(f"Gateway exited with code {self.process.returncode}")

    def get_status(self) -> dict:
        pid = None
        if self.process and self.process.returncode is None:
            pid = self.process.pid
        uptime = None
        if self.start_time and self.state == "running":
            uptime = int(time.time() - self.start_time)
        return {
            "state": self.state,
            "pid": pid,
            "uptime": uptime,
            "restart_count": self.restart_count,
        }


gateway = GatewayManager()
config_lock = asyncio.Lock()


async def homepage(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    return templates.TemplateResponse(request, "index.html")


async def health(request: Request):
    return JSONResponse({"status": "ok", "gateway": gateway.state})


async def api_config_get(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    config = load_config()
    return JSONResponse(mask_secrets(config))


async def api_config_put(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    try:
        restart = body.pop("_restartGateway", False)

        async with config_lock:
            existing = load_config()
            merged = merge_secrets(body, existing)
            save_config(merged)

        if restart:
            asyncio.create_task(gateway.restart())

        return JSONResponse({"ok": True, "restarting": restart})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_status(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err

    config = load_config()

    providers = {}
    for name, prov in config.get("providers", {}).items():
        providers[name] = {"configured": bool(prov.get("api_key"))}

    channels = {}
    for name, chan in config.get("channels", {}).items():
        channels[name] = {"enabled": chan.get("enabled", False)}

    # Check model_list for configured models
    model_list = config.get("model_list", [])
    models = {}
    for m in model_list:
        if m.get("model_name"):
            models[m["model_name"]] = {"configured": bool(m.get("api_key"))}

    cron_dir = CONFIG_DIR / "cron"
    cron_jobs = []
    if cron_dir.exists():
        for f in cron_dir.glob("*.json"):
            try:
                cron_jobs.append(json.loads(f.read_text()))
            except Exception:
                pass

    return JSONResponse({
        "gateway": gateway.get_status(),
        "providers": providers,
        "channels": channels,
        "models": models,
        "cron": {"count": len(cron_jobs), "jobs": cron_jobs},
    })


async def api_logs(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    return JSONResponse({"lines": list(gateway.logs)})


async def api_gateway_start(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.start())
    return JSONResponse({"ok": True})


async def api_gateway_stop(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.stop())
    return JSONResponse({"ok": True})


async def api_gateway_restart(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.restart())
    return JSONResponse({"ok": True})


async def auto_start_gateway():
    config = load_config()
    has_key = False
    for prov in config.get("providers", {}).values():
        if isinstance(prov, dict) and prov.get("api_key"):
            has_key = True
            break
    # Also check model_list for API keys
    if not has_key:
        for m in config.get("model_list", []):
            if isinstance(m, dict) and m.get("api_key"):
                has_key = True
                break
    if has_key:
        asyncio.create_task(gateway.start())


routes = [
    Route("/", homepage),
    Route("/health", health),
    Route("/api/config", api_config_get, methods=["GET"]),
    Route("/api/config", api_config_put, methods=["PUT"]),
    Route("/api/status", api_status),
    Route("/api/logs", api_logs),
    Route("/api/gateway/start", api_gateway_start, methods=["POST"]),
    Route("/api/gateway/stop", api_gateway_stop, methods=["POST"]),
    Route("/api/gateway/restart", api_gateway_restart, methods=["POST"]),
]

app = Starlette(
    routes=routes,
    middleware=[Middleware(AuthenticationMiddleware, backend=BasicAuthBackend())],
    on_startup=[auto_start_gateway],
    on_shutdown=[gateway.stop],
)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info", loop="asyncio")
    server = uvicorn.Server(config)

    def handle_signal():
        loop.create_task(gateway.stop())
        server.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)

    loop.run_until_complete(server.serve())