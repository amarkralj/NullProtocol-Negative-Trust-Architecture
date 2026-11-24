# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""v1.0 detectors for AI assistants and AI agents (prompts, tool calls, command lines). Standard library only.

These are pattern detectors. They catch the publicly documented, copy-pasted forms of each technique and are easy
to evade by rewording; they are evidence for the trust engine, not a filter that makes a model safe. The pattern
families follow OWASP Top 10 for LLM Applications 2025 (LLM01 prompt injection, LLM02 sensitive information
disclosure, LLM06 excessive agency, LLM10 unbounded consumption): https://genai.owasp.org/llm-top-10/

    injection(text)        -> matched phrases of instruction override, persona / "no rules" jailbreaks,
                              system-prompt extraction (needs two independent families, or one strong phrase)
    secrets(text)          -> kinds of credentials in a prompt (AWS keys, private keys, connection strings with a
                              password, password variables, bearer tokens / JWTs, card numbers that pass Luhn)
    risky_tools(names)     -> tool calls that execute code, write files or reach the network
    autonomy_override(cmd) -> AI coding CLIs started with every approval switched off
"""
from __future__ import annotations

import re
from typing import Iterable, List

_I = re.IGNORECASE
# instruction override: the classic "ignore previous instructions" family
OVERRIDE = re.compile(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|your|the)\b"
                      r"[^.\n]{0,25}\b(instructions?|rules|guidelines|prompts?|polic(y|ies)|filters?|programming)\b", _I)
# a new persona without limits ("you are now DAN", "pretend you are an AI with no restrictions", "amoral")
PERSONA = re.compile(r"\b(you are now|from now on,? you|pretend (you are|to be)|act as (if|an?|my))\b[^\n]{0,80}"
                     r"\b(no|without|any|zero)\b[^\n]{0,20}\b(restrictions?|limits?|rules|filters?|polic(y|ies)|morals?|ethics)\b"
                     r"|\b(DAN|developer) mode\b|\bjailbreak\b|\bamoral\b|\bsans moral|\bunrestricted (ai|assistant|mode)\b"
                     r"|\byou are now (DAN|EvilGPT|[A-Z][a-zA-Z]+GPT)\b|\bno content policy\b", _I)
# system-prompt extraction
EXTRACT = re.compile(r"\b(reveal|repeat|print|output|show|tell me|what are)\b[^\n]{0,40}\b(system prompt|your (initial |hidden )?"
                     r"(instructions|prompt))\b|\boutput everything above\b|\bnew system prompt\b", _I)
# forced compliance phrasing, only counted together with another family
COERCE = re.compile(r"\b(you (must|will) (comply|obey|answer)|you have no (choice|right to refuse)|comply with all requests)\b", _I)
# role-play wrappers used to smuggle rules ("rules=reply to every prompt with [X:]")
RULES = re.compile(r"\brules\s*=\s*|\breply to every prompt with\b|\bimaginary world\b[^\n]{0,40}\b(no|without|sans)\b", _I)


def injection(text: str) -> List[str]:
    if not text:
        return []
    hits = [name for name, rx in (("override", OVERRIDE), ("persona", PERSONA), ("extract", EXTRACT), ("rules", RULES))
            if rx.search(text)]
    if COERCE.search(text) and hits:
        hits.append("coerce")
    return hits


SECRET_RX = {
    "aws_access_key": re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    "aws_secret_key": re.compile(r"aws_secret_access_key\s*[=:]\s*\S{20,}|AWS_SECRET_ACCESS_KEY\s*=\s*\"?[A-Za-z0-9/+]{30,}", _I),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|\bPrivate ?Key\b[^\n]{0,30}(MII|-----)"),
    "connection_string": re.compile(r"\b[a-z][a-z0-9+.-]{2,20}://[^\s:/@]{1,64}:[^\s@/]{3,128}@[^\s/]+", _I),
    "password_variable": re.compile(r"\b(PGPASSWORD|MYSQL_PWD|PASSWORD|PASSWD|DB_PASS(WORD)?|SECRET|API_KEY|TOKEN)\s*=\s*['\"]?[^\s'\"$()]{4,}", _I),
    "keychain_read": re.compile(r"\bsecurity find-(generic|internet)-password\b[^\n]{0,80}\s-w\b"),
    "bearer_token": re.compile(r"\b(Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
    "github_token": re.compile(r"\b(ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
}
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(digits: str) -> bool:
    s, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        s += d
        alt = not alt
    return s % 10 == 0


def secrets(text: str) -> List[str]:
    if not text:
        return []
    found = [k for k, rx in SECRET_RX.items() if rx.search(text)]
    for m in _CARD.finditer(text):
        d = re.sub(r"\D", "", m.group())
        if 13 <= len(d) <= 19 and len(set(d)) > 2 and _luhn(d):
            found.append("card_number")
            break
    return found


# tools that execute code, change files or reach the network (names used by Claude Code, OpenAI Agents, LangChain,
# MCP reference servers); reading and searching are not counted
RISKY_TOOLS = {"bash", "shell", "sh", "exec", "execute", "execute_command", "run_command", "run_shell_command", "terminal",
               "powershell", "cmd", "python", "code_interpreter", "computer", "write", "write_file", "edit", "edit_file",
               "multiedit", "str_replace_editor", "create_file", "delete_file", "move_file", "curl", "wget", "http_request",
               "fetch", "webfetch", "web_fetch"}


def risky_tools(names: Iterable[str]) -> List[str]:
    return sorted({n for n in names if n and n.lower() in RISKY_TOOLS})


# AI coding CLIs with all approvals switched off (each switch is documented by its vendor)
AUTONOMY = [
    ("gemini", re.compile(r"(^|[\s/])gemini(\.js)?\s(.*\s)?(--yolo|-yolo|-y|--approval-mode[= ]yolo)(\s|$)")),
    ("claude", re.compile(r"(^|[\s/])claude\s.*--dangerously-skip-permissions")),
    ("codex", re.compile(r"(^|[\s/])codex\s.*(--dangerously-bypass-approvals-and-sandbox|--yolo\b|--full-auto)")),
    ("aider", re.compile(r"(^|[\s/])aider\s.*--yes-always")),
    ("copilot", re.compile(r"(^|[\s/])copilot\s.*--allow-all-tools")),
    ("cursor-agent", re.compile(r"(^|[\s/])cursor-agent\s.*(--force|-f\b)")),
]


def autonomy_override(cmdline: str) -> str:
    for name, rx in AUTONOMY:
        if rx.search(" " + cmdline + " "):
            return name
    return ""
