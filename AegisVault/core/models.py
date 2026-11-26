from pydantic import BaseModel, Field

class AssessmentRequest(BaseModel):
    # Paste authorised offline records only. Supports Linux shadow rows,
    # Windows SAM-export rows and raw digests. No live extraction is performed.
    records: list[str] = Field(min_length=1, max_length=100)
    candidate_words: list[str] = Field(default_factory=list, max_length=5000)
    include_common_candidates: bool = True
