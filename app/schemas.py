from typing import Any

from pydantic import BaseModel, Field


class ToolRequest(BaseModel):
    action: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)


class DocumentSummaryArguments(BaseModel):
    document: str = Field(min_length=1, max_length=10000)


class TicketArguments(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=3000)


class DocumentAnalysisRequest(BaseModel):
    document: str = Field(min_length=1, max_length=10000)
    proposed_action: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)