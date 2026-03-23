from pydantic import BaseModel, Field
from pydantic import ConfigDict
from typing import Literal


class ScanConfig(BaseModel):
    """
    Mirrors the TypeScript ScanConfig interface.
    The frontend serialises this with camelCase keys, so aliases are required.
    """

    model_config = ConfigDict(populate_by_name=True)

    use_llm: bool = Field(True, alias="useLLM")
    llm_provider: Literal["snowflake_cortex", "openai", "anthropic"] = Field(
        "snowflake_cortex", alias="llmProvider"
    )
    use_snowflake: bool = Field(False, alias="useSnowflake")
    report_formats: list[Literal["json", "html", "markdown"]] = Field(
        default_factory=lambda: ["json", "html"], alias="reportFormats"
    )
