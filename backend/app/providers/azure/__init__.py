

def enum_text(value: object) -> str:
    """The plain text of an Azure SDK enum value.

    Newer SDKs return str-based enums whose str() is 'RunbookState.PUBLISHED',
    not 'Published', so comparing str(value) to a literal silently never
    matches. Always compare through this.
    """
    if value is None:
        return ""
    raw = getattr(value, "value", value)
    return str(raw)

