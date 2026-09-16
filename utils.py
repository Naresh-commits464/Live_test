def normalize_name(name: str) -> str:
    return " ".join(name.strip().split()).title()

def is_positive(value: int) -> bool:
    return value > 0
