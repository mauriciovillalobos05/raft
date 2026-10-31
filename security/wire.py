"""Strict JSON messages passed by value; never unpickle or dereference callers."""
import json
from typing import Annotated
from pydantic import BaseModel, ConfigDict, Field

Text = Annotated[str, Field(min_length=1, max_length=65536)]
Index = Annotated[int, Field(ge=-1)]
Term = Annotated[int, Field(ge=0)]


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Vote(Message):
    candidate_id: Text
    current_term: Term
    last_log_index: Index
    last_log_term: Term


class Entry(Message):
    term: Term
    command: Text


class Heartbeat(Message):
    leader_id: Text
    current_term: Term
    prev_log_index: Index
    prev_log_term: Term
    entries: Annotated[list[Entry], Field(max_length=1000)] = []
    leader_commit: Index


class Key(Message):
    key: Text
    timestamp: Annotated[int, Field(ge=0)]


class Read(Key):
    field: Text


class Set(Read):
    value: Annotated[str, Field(max_length=65536)]
    ttl: Annotated[int, Field(ge=0)] | None = None


class ScanPrefix(Key):
    prefix: Annotated[str, Field(max_length=65536)]


def decode(payload, model):
    if type(payload) is not str or len(payload.encode()) > 1024 * 1024:
        raise ValueError("Expected a JSON string no larger than 1 MiB")
    return model.model_validate_json(payload)


def encode(payload):
    return json.dumps(payload, allow_nan=False)
