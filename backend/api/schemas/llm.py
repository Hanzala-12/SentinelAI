from pydantic import BaseModel, Field, HttpUrl


class DeepExplainRequest(BaseModel):
    url: HttpUrl
    page_text: str | None = Field(default=None, max_length=20000)
    risk_score: int = Field(ge=0, le=10)


class DeepExplainResponse(BaseModel):
    explanation: str
    model: str
    used_llm: bool
