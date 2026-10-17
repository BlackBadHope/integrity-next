"""One generic official-origin policy shared by schema and handoff state."""
import re

CONVERSATION_PREFIX = "https://" + "chatgpt.com" + "/c/"
CONVERSATION_PATTERN = r"^https://" + re.escape("chatgpt.com") + r"/c/[A-Za-z0-9:-]{16,128}$"
