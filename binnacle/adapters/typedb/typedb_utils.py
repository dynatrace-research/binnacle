from pydantic import BaseModel


def get_alias_lookup_table(cls: BaseModel) -> dict[str, str]:
    aliases = {}
    for field_name, field in cls.model_fields.items():
        if field.alias is not None:
            aliases[field.alias] = field_name
    return aliases
