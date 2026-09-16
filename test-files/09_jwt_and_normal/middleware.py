# Synthetic JWT-shaped value for testing only.
AUTHORIZATION = "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.TEST_SIGNATURE_ONLY"

def authorized(user: str) -> bool:
    return bool(user)
