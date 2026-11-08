"""
A compact, dependency-free check for the passwords attackers try first.

Length alone (the portal requires 12+) does not stop "Welcome2026!!",
"Password1234" or "qwertyuiop12": they are long enough and near the top of
every guessing list. weak_password_reason() rejects a password that can be
built ENTIRELY from predictable pieces:

  - at most two common words or names (the list below, matched also through
    the usual letter-for-symbol swaps: P@ssw0rd -> password) or parts of the
    account's own username,
  - plus any number of digit runs (years, 1234...), runs of symbols or spaces,
    runs of one repeated character, keyboard walks (qwerty, 1qaz2wsx, asdf...)
    and alphabet runs (abcd...).

Anything with a part outside those (a random password, or a passphrase of
three or more words that are not all on the list, such as "correct horse
battery") passes. This is a short-list check, not a full breach corpus.
"""
from functools import lru_cache

# Base words of the most common passwords (breach-list top entries, seasons,
# months, days, and words people use for work accounts). Lower case, 3+ letters.
COMMON_WORDS = frozenset("""
password passwd pass passw0rd secret letmein welcome hello hi login logon admin administrator
root user guest test testing demo default changeme change temp temporary qwerty
iloveyou love lovely loveme monkey dragon football baseball soccer basketball hockey
sunshine princess shadow master superman batman spiderman michael jordan freedom
whatever trustno trust starwars computer internet server system office company
business money family flower friend friends angel baby cookie chocolate cheese
pokemon naruto doraemon pikachu hellokitty kitty tiger lion cat dog dogs puppy
apple orange banana summer winter spring autumn fall season january february march
april may june july august september october november december monday tuesday
wednesday thursday friday saturday sunday morning night happy lucky magic star
world home house heaven killer ninja samurai sakura tokyo osaka kyoto yokohama
nagoya sapporo fukuoka japan nihon nippon eset soc security secure portal client
access account network cloud google microsoft windows apple amazon facebook
qazwsx asdf zxcv abc abcd god jesus blessed hunter ranger thunder silver golden
gold black white blue red green purple matrix mustang charlie robert thomas daniel
jennifer jessica ashley david james john maria anna yuki hiroshi takashi kenji
""".split())

# Keyboard rows and common walk shapes; any 3+ character piece of one, forward
# or backward, counts as a walk.
_WALKS = (
    "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p", "qazwsxedcrfvtgbyhnujmikolp",
    "1q2w3e4r5t6y7u8i9o0p", "q1w2e3r4t5y6u7i8o9p0", "zaq1xsw2cde3vfr4bgt5",
    "!@#$%^&*()", "abcdefghijklmnopqrstuvwxyz",
)
_WALK_PIECES = frozenset(
    s[i:j] for w in _WALKS for s in (w, w[::-1])
    for i in range(len(s)) for j in range(i + 3, len(s) + 1)
)
_LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i", "|": "i",
                       "3": "e", "$": "s", "5": "s", "7": "t", "+": "t", "8": "b", "9": "g"})
_MAX_WORDS = 2
_MAX_WORD_LEN = max(len(w) for w in COMMON_WORDS)


def _username_parts(username: str | None) -> set[str]:
    if not username:
        return set()
    name = username.strip().lower()
    parts = {name}
    for sep in "._@-":
        name = name.replace(sep, " ")
    parts.update(p for p in name.split() if len(p) >= 3)
    return {p for p in parts if len(p) >= 3}


@lru_cache(maxsize=256)
def _min_words(raw: str, plain: str, user_parts: frozenset[str]) -> int | None:
    """Fewest word pieces needed to cover the whole password with predictable
    pieces, or None when some part of it is not predictable."""
    n = len(raw)
    inf = n + 1
    best = [inf] * (n + 1)
    best[0] = 0
    for i in range(n):
        if best[i] == inf:
            continue
        # free pieces: digit run, symbol/space run, repeated character, walk
        j = i
        while j < n and raw[j].isdigit():
            j += 1
        for k in range(i + 1, j + 1):
            best[k] = min(best[k], best[i])
        j = i
        while j < n and not raw[j].isalnum():
            j += 1
        for k in range(i + 1, j + 1):
            best[k] = min(best[k], best[i])
        j = i + 1
        while j < n and raw[j] == raw[i]:
            j += 1
        if j - i >= 3:
            for k in range(i + 3, j + 1):
                best[k] = min(best[k], best[i])
        for k in range(i + 3, n + 1):
            if raw[i:k] in _WALK_PIECES:
                best[k] = min(best[k], best[i])
        # word pieces: a common word or a part of the username, as typed or
        # with symbol-for-letter swaps undone
        for k in range(i + 3, min(n, i + max(_MAX_WORD_LEN, 64)) + 1):
            piece_raw, piece_plain = raw[i:k], plain[i:k]
            if (piece_plain in COMMON_WORDS or piece_raw in COMMON_WORDS
                    or piece_raw in user_parts or piece_plain in user_parts):
                best[k] = min(best[k], best[i] + 1)
    return best[n] if best[n] != inf else None


def weak_password_reason(password: str, username: str | None = None) -> str | None:
    """A short reason when `password` is one attackers guess early, else None."""
    raw = password.lower()
    words = _min_words(raw, raw.translate(_LEET), frozenset(_username_parts(username)))
    if words is not None and words <= _MAX_WORDS:
        return ("Password is too easy to guess (common words, names, dates, keyboard "
                "patterns or the username). Use a longer phrase or a generated password")
    return None
