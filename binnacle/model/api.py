from pydantic import BaseModel, validator


class NewProjectRequest(BaseModel):
    cluster: str
    name: str | None = None  # if not present, context name will be used
    namespaces: list[str] | None = None

    # TODO[pydantic]: We couldn't refactor the `validator`, please replace it by `field_validator` manually.
    # Check https://docs.pydantic.dev/dev-v2/migration/#changes-to-validators for more information.
    @validator("name", always=True)
    def use_context_name_as_fallback(cls, value, values):
        if value is None:
            return values["cluster"]
        return value
