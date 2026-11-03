"""The number extractor and the check that keeps invented numbers out of the Reporter's prose.

:func:`numbers_of` finds every number a text *claims*, whatever its dress (digits in any script,
number words, ordinals, percentages, ranges, times and dates, multipliers, units) and
:func:`unknown` returns those the report's input does not hold, so one invented number rejects the
whole prose. The check is exact (``67%`` is not ``66.7``) and **fails closed**: whatever the
extractor cannot read exactly (:func:`unreadable`) is refused, not guessed at."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from fractions import Fraction

Need = frozenset[Fraction]  # any one of these satisfies one required value
MAX_DIGITS = 60
NEVER = Fraction(-1)  # a figure no input can hold (values are magnitudes, never negative)


@dataclass(frozen=True)
class Found:
    """One number a text claims."""

    kind: str  # digits word ordinal percent time date dotted range radix roman cjk
    raw: str
    needs: tuple[Need, ...]  # every value this claim needs, each satisfied by any alternative
    unit: str | None = None  # the unit after it, when it has a known one
    exact: frozenset[str] = frozenset()  # a time, date or dotted number: its spellings

    @property
    def values(self) -> tuple[Fraction, ...]:
        """The first alternative of each needed value (for tests and messages)."""
        return tuple(min(n) for n in self.needs)


def clean(text: str) -> str:
    """The text as a reader sees it: compatibility forms folded (NFKC), digits of every script
    read as ASCII, invisible characters and combining marks dropped, other control characters
    a space, CJK numerals written as digits between spaces."""
    out: list[str] = []
    for char in unicodedata.normalize("NFKC", text):
        category = unicodedata.category(char)
        if category == "Nd":
            out.append(str(unicodedata.decimal(char)))
        elif category in ("Cf", "Mn", "Me"):
            continue
        elif category == "Cc" and char not in "\t\n\r":
            out.append(" ")
        elif category in ("Lo", "No", "Nl") and unicodedata.numeric(char, None) is not None:
            value = Fraction(unicodedata.numeric(char))
            out.append(
                f" {value.numerator} "
                if value.denominator == 1
                else f" {value.numerator}/{value.denominator} "
            )
        else:
            out.append(char)
    return "".join(out)


_ONES = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
    "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19,
}  # fmt: skip
_TENS = {
    "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70,
    "eighty": 80, "ninety": 90,
}  # fmt: skip
_SCALES = {"thousand": 10**3, "million": 10**6, "billion": 10**9, "trillion": 10**12}
_PLURALS = {
    "hundreds": 100, "thousands": 10**3, "millions": 10**6, "billions": 10**9, "dozens": 12,
    "dozen": 12, "score": 20, "scores": 20,
}  # fmt: skip
_SINGLES: dict[str, int | Fraction] = {
    "none": 0, "nil": 0, "once": 1, "single": 1, "twice": 2, "thrice": 3, "double": 2,
    "triple": 3, "quadruple": 4, "pair": 2, "pairs": 2, "couple": 2, "trio": 3, "duo": 2,
    "both": 2, "half": Fraction(1, 2), "halves": Fraction(1, 2), "quarter": Fraction(1, 4),
    "quarters": Fraction(1, 4), "thirds": Fraction(1, 3), "fifths": Fraction(1, 5),
    "tenths": Fraction(1, 10), "noon": 12, "midnight": 0,
}  # fmt: skip
_ORDINALS = {
    "first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5, "sixth": 6, "seventh": 7,
    "eighth": 8, "ninth": 9, "tenth": 10, "eleventh": 11, "twelfth": 12, "thirteenth": 13,
    "fourteenth": 14, "fifteenth": 15, "sixteenth": 16, "seventeenth": 17, "eighteenth": 18,
    "nineteenth": 19, "twentieth": 20, "thirtieth": 30, "fortieth": 40, "fiftieth": 50,
    "sixtieth": 60, "seventieth": 70, "eightieth": 80, "ninetieth": 90, "hundredth": 100,
    "thousandth": 1000, "millionth": 10**6,
}  # fmt: skip
_UNIT_BEFORE_SECOND = frozenset({"per", "each", "every"})

# a unit word after a number -> its canonical name (the units of argus.reporter.model)
_UNITS: dict[str, str] = {}
for _canon, _names in {
    "percent": "% percent pct", "ms": "ms millisecond milliseconds msec",
    "second": "s sec secs second seconds", "minute": "min mins minute minutes",
    "hour": "h hr hrs hour hours", "day": "d day days", "week": "w wk week weeks",
    "month": "month months", "year": "yr yrs year years",
    "kb": "kb kib", "mb": "mb mib", "gb": "gb gib", "tb": "tb tib", "byte": "b byte bytes",
}.items():  # fmt: skip
    for _name in _names.split():
        _UNITS[_name] = _canon
_UNITS["per cent"] = "percent"

# every hyphen, dash and minus sign (NFKC maps some to "-"; the rest stay)
_DASHES = "-\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u2043\ufe58\ufe63\uff0d"
_DASH_CLASS = "".join(re.escape(c) for c in _DASHES)
_N = r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?"
_MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
_MONTH = (
    r"(?P<{n}>jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
    r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\b\.?"
)
_NAMED = (
    r"(?<!\d)(?:(?P<d1>\d{1,2})(?:st|nd|rd|th)?\s+" + _MONTH.format(n="m1")
    + r"(?:,?\s+(?P<y1>\d{4})(?!\d))?"
    + r"|" + _MONTH.format(n="m2") + r"\s+(?P<d2>\d{1,2})(?:st|nd|rd|th)?(?!\d)"
    + r"(?:,?\s+(?P<y2>\d{4})(?!\d))?)"
)  # fmt: skip
_MASTER = re.compile(
    r"(?P<radix>(?<![0-9A-Za-z])0(?:[xX][0-9a-fA-F]+|[bB][01]+|[oO][0-7]+))"
    r"|(?P<sci>(?<![0-9.])\d+(?:\.\d+)?[eE][+-]?\d+)"
    r"|(?P<date>(?<!\d)\d{4}-\d{2}-\d{2}(?!\d))"
    r"|(?P<named>(?i:" + _NAMED + r"))"
    r"|(?P<time>(?<!\d)\d{1,2}:\d{2}(?::\d{2})?(?:\s*[aApP]\.?[mM]\b\.?)?)"
    r"|(?P<dotted>\d+(?:\.\d+){2,})"
    r"|(?P<spaced>(?<![\d.,])\d{1,3}(?:[ _']\d{3})+(?![\d,]))"
    rf"|(?P<range>(?:{_N})\s*(?:[{_DASH_CLASS}~]|\bto\b)\s*(?:{_N})"
    rf"|(?<=[Bb]etween\s)(?:{_N})\s+and\s+(?:{_N}))"
    rf"|(?P<num>{_N})"
    r"|(?P<word>[A-Za-z]+)"
)
_SUFFIX = re.compile(
    r"(?:\s?(?P<w>thousand|million|billion|trillion|bn)\b|(?P<c>[kKM])(?![A-Za-z]))"
)
_UNIT_AFTER = re.compile(r"\s?(?P<u>%|per\s+cent\b|[A-Za-z]+)")
_ROMAN = re.compile(r"M{0,3}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})")
_ROMAN_VALUES = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}
_SCALE_WORD = {"k": 10**3, "K": 10**3, "M": 10**6, "thousand": 10**3, "million": 10**6,
               "billion": 10**9, "trillion": 10**12, "bn": 10**9}  # fmt: skip
_TIME_PARTS = re.compile(r"(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*([aApP])\.?[mM]\.?)?")
_JOIN = re.compile(rf"[\s{_DASH_CLASS}]*")
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _decimal(token: str) -> Fraction:
    digits = token.replace(",", "")
    if len(digits.replace(".", "")) > MAX_DIGITS:
        return NEVER
    try:
        return Fraction(Decimal(digits))
    except (InvalidOperation, ValueError):  # pragma: no cover - the pattern only gives digits
        return NEVER


def _need(*values: Fraction | int) -> Need:
    return frozenset(Fraction(v) for v in values)


def _unit_at(text: str, end: int) -> tuple[str | None, int]:
    """The canonical unit written right after ``end`` and where it ends."""
    found = _UNIT_AFTER.match(text, end)
    if found is None:
        return None, end
    word = " ".join(found["u"].lower().split())
    unit = _UNITS.get(word)
    if unit is None:
        return None, end
    return unit, found.end()


def _time_found(raw: str) -> Found:
    match = _TIME_PARTS.fullmatch(raw)
    assert match is not None
    hour, minute = int(match[1]), int(match[2])
    second = int(match[3]) if match[3] is not None else None
    mark = match[4].lower() if match[4] else None
    hours = {hour}
    clock = hour
    if mark is not None and 1 <= hour <= 12:
        clock = hour % 12 + (12 if mark == "p" else 0)
        hours = {clock, hour}
    stamp = f"{clock:02d}:{minute:02d}"
    exact = {stamp + (f":{second:02d}" if second is not None else "")}
    if second == 0:
        exact.add(stamp)
    needs = [_need(*hours), _need(minute)]
    if second is not None:
        needs.append(_need(second))
    return Found("time", raw, tuple(needs), exact=frozenset(exact))


def _named(match: re.Match[str]) -> Found:
    """``20 Oct 2026``, ``Oct 20`` and the like: a date to be matched whole (no year: day and
    month only)."""
    day = int(match["d1"] or match["d2"])
    month = _MONTHS.index((match["m1"] or match["m2"])[:3].lower()) + 1
    year = match["y1"] or match["y2"]
    needs = [_need(day)]
    if year is not None:
        needs.append(_need(int(year)))
        exact = f"{int(year):04d}-{month:02d}-{day:02d}"
    else:
        exact = f"--{month:02d}-{day:02d}"
    return Found("date", match.group(), tuple(needs), exact=frozenset({exact}))


def _decimal_exp(raw: str) -> Fraction:
    mantissa, _, exponent = raw.lower().partition("e")
    exp = int(exponent)
    if abs(exp) > 40 or len(mantissa.replace(".", "")) > MAX_DIGITS:
        return NEVER
    return _decimal(mantissa) * Fraction(10) ** exp


def _digits(text: str, match: re.Match[str]) -> tuple[Found, int]:
    value = _decimal(match.group())
    end = match.end()
    suffix = _SUFFIX.match(text, end)
    if suffix is not None:
        if value != NEVER:
            value *= _SCALE_WORD[suffix["w"] or suffix["c"]]
        end = suffix.end()
    unit, unit_end = _unit_at(text, end)
    kind = "percent" if unit == "percent" else "digits"
    return Found(kind, text[match.start() : unit_end], (_need(value),), unit), unit_end


# Two-letter capitals that are Roman numerals but far more often something else in this text
ACRONYMS = frozenset({"MX", "DC", "CD", "MD", "CC", "MM", "DM", "MC", "LC", "CV", "MI", "DI",
                      "LI", "CM", "CI", "CL", "DL", "ML", "MIX"})  # fmt: skip


def _roman(word: str) -> int | None:
    if len(word) < 2 or not word.isupper() or word in ACRONYMS or not _ROMAN.fullmatch(word):
        return None
    total = 0
    for char, after in zip(word, [*word[1:], ""], strict=True):
        value = _ROMAN_VALUES[char]
        total += -value if after and _ROMAN_VALUES[after] > value else value
    return total


def _kind(word: str) -> str | None:
    if word in _ONES:
        return "ones" if _ONES[word] < 10 else "teen"
    if word in _TENS:
        return "tens"
    if word == "hundred":
        return "hundred"
    if word in _SCALES:
        return "scale"
    return None


def _may_follow(last: str, kind: str, word: str) -> bool:
    if word == "zero":
        return False
    if last in ("ones", "teen"):
        return kind in ("hundred", "scale")
    if last == "tens":
        return kind in ("ones", "hundred", "scale") and word != "ten"
    if last == "hundred":
        return kind in ("ones", "teen", "tens", "scale")
    if last == "scale":
        return kind in ("ones", "teen", "tens", "hundred")
    return True


_TO = re.compile(r"\s+to\s+", re.IGNORECASE)
_AND = re.compile(r"\s+and\s+", re.IGNORECASE)
_BETWEEN = re.compile(r"[Bb]etween\s+$")


def _words(words: list[tuple[str, int, int]], text: str) -> list[tuple[int, Found]]:
    """Number words, ordinals and the like among the words of ``text`` (start, end each), each
    with where it starts. ``three to seven`` and ``between three and seven`` are one range."""
    spans = _word_runs(words, text)
    merged: list[tuple[int, Found]] = []
    i = 0
    while i < len(spans):
        start, end, item = spans[i]
        nxt = spans[i + 1] if i + 1 < len(spans) else None
        if nxt is not None and item.kind == "word" and nxt[2].kind == "word":
            gap = text[end : nxt[0]]
            joined = _TO.fullmatch(gap) or (_AND.fullmatch(gap) and _BETWEEN.search(text[:start]))
            if joined:
                both = Found("range", f"{item.raw} - {nxt[2].raw}", item.needs + nxt[2].needs,
                             nxt[2].unit)  # fmt: skip
                merged.append((start, both))
                i += 2
                continue
        merged.append((start, item))
        i += 1
    return merged


def _word_runs(words: list[tuple[str, int, int]], text: str) -> list[tuple[int, int, Found]]:
    """Each number word, run of them, ordinal and the like: (start, end, claim)."""
    found: list[tuple[int, int, Found]] = []
    i = 0
    resume = 0
    while i < len(words):
        raw, start, end = words[i]
        if start < resume:
            i += 1
            continue
        low = raw.lower()
        kind = _kind(low)
        if kind is None:
            i += 1
            single = _single(low, raw, start, text)
            if single is not None:
                found.append((start, end, single))
            continue
        total, current, last = Fraction(0), Fraction(0), ""
        spelled = [low]
        j = i
        while True:
            word = words[j][0].lower()
            kind = _kind(word)
            assert kind is not None
            if kind in ("ones", "teen", "tens"):
                current += _ONES.get(word, _TENS.get(word, 0))
            elif kind == "hundred":
                current = (current or Fraction(1)) * 100
            else:
                total += (current or Fraction(1)) * _SCALES[word]
                current = Fraction(0)
            last = kind
            end = words[j][2]
            nxt = _next_member(words, j, text, last)
            if nxt is None:
                break
            j = nxt
            spelled.append(words[j][0].lower())
        unit, unit_end = _unit_at(text, end)
        kind_name = "percent" if unit == "percent" else "word"
        claim = Found(kind_name, " ".join(spelled), (_need(total + current),), unit)
        resume = unit_end if unit is not None else end
        found.append((start, resume, claim))
        i = j + 1
    return found


def _next_member(words: list[tuple[str, int, int]], j: int, text: str, last: str) -> int | None:
    """The index of the word that continues the number ending at word ``j``, if any."""
    k = j + 1
    if k >= len(words):
        return None
    if not _JOIN.fullmatch(text[words[j][2] : words[k][1]]):
        return None
    if words[k][0].lower() == "and" and last in ("hundred", "scale"):
        nxt = k + 1
        if nxt < len(words) and _JOIN.fullmatch(text[words[k][2] : words[nxt][1]]):
            word = words[nxt][0].lower()
            kind = _kind(word)
            if kind in ("ones", "teen", "tens") and _may_follow(last, kind, word):
                return nxt
        return None
    word = words[k][0].lower()
    kind = _kind(word)
    if kind is None or not _may_follow(last, kind, word):
        return None
    return k


def _single(low: str, raw: str, start: int, text: str) -> Found | None:
    if low in _SINGLES:
        return Found("word", raw, (_need(_SINGLES[low]),))
    if low in _PLURALS:
        return Found("word", raw, (_need(_PLURALS[low]),))
    if low in _ORDINALS:
        before = re.search(r"([A-Za-z]+|\d)\s*$", text[:start])
        if (
            low == "second"
            and before is not None
            and (
                before[1].isdigit()
                or before[1].lower() in _UNIT_BEFORE_SECOND
                or _kind(before[1].lower()) is not None
            )
        ):
            return None  # a unit of time after a number, per, each or every
        return Found("ordinal", raw, (_need(_ORDINALS[low]),))
    roman = _roman(raw)
    if roman is not None:
        return Found("roman", raw, (_need(roman),))
    return None


def numbers_of(text: str) -> list[Found]:
    """Every number ``text`` claims, in the order it is written (see the module docstring)."""
    text = clean(text)
    found: list[tuple[int, Found]] = []
    words: list[tuple[str, int, int]] = []
    skip = 0
    for match in _MASTER.finditer(text):
        if match.start() < skip:
            continue
        kind = match.lastgroup
        raw = match.group()
        end = match.end()
        item: Found
        if kind == "word":
            words.append((raw, match.start(), end))
            continue
        if kind == "radix":
            base = {"x": 16, "b": 2, "o": 8}[raw[1].lower()]
            item = Found("radix", raw, (_need(int(raw[2:], base)),)) if len(raw) < 40 else (
                Found("radix", raw, (_need(NEVER),)))  # fmt: skip
        elif kind == "sci":
            item = Found("digits", raw, (_need(_decimal_exp(raw)),))
        elif kind == "date":
            year, month, day = (int(p) for p in raw.split("-"))
            item = Found("date", raw, (_need(year), _need(month), _need(day)),
                         exact=frozenset({raw}))  # fmt: skip
        elif kind == "time":
            item = _time_found(raw)
        elif kind == "dotted":
            parts = tuple(_need(int(p)) if len(p) <= MAX_DIGITS else _need(NEVER)
                          for p in raw.split("."))  # fmt: skip
            item = Found("dotted", raw, parts, exact=frozenset({raw}))
        elif kind == "named":
            item = _named(match)
        elif kind == "spaced":
            groups = raw.replace("_", " ").replace("'", " ").split()
            joined = _decimal("".join(groups))
            item = Found("digits", raw, (_need(joined), *(_need(int(g)) for g in groups)))
        elif kind == "range":
            ends = re.findall(_N, re.sub(r"\b(?:to|and)\b", " ", raw))
            unit, end = _unit_at(text, end)
            item = Found("range", raw, tuple(_need(_decimal(e)) for e in ends), unit)
        else:
            item, end = _digits(text, match)
        found.append((match.start(), item))
        skip = end
    found += _words(words, text)
    return [item for _, item in sorted(found, key=lambda pair: pair[0])]


# Words that multiply the number before them (or stand for a number) that the extractor does not
# read exactly: a text that uses one is refused, whatever the input holds.
MULTIPLIERS = frozenset({
    "lakh", "lakhs", "lac", "lacs", "crore", "crores", "cr", "k", "mil", "mils", "mln", "mlns",
    "mn", "bn", "thou", "thous", "grand", "grands", "dozen", "dozens", "score", "scores", "gross",
    "fold", "folds",
})  # fmt: skip
_COMMA_RUN = re.compile(r"\d+(?:[,\u060c\u066b\u066c\u201a]\d+)+")
_GROUPING = re.compile(r"\d{1,3}(?:,\d{3})+")
_LETTERS = re.compile(r"[^\W\d_]+")
_AFTER_NUMBER = re.compile(r"\d\s?[kKmM](?![^\W\d_])")  # 5 k, 5M, 5 m
_ROMAN_ANY = re.compile(_ROMAN.pattern, re.IGNORECASE)
_MULTIPLIER_ENDS = ("fold", "folds", "score", "scores")


def _visible(norm: str) -> str:
    """NFKC text as a reader sees it: invisible characters and combining marks dropped, other
    control characters (but tab, newline, return) a space."""
    out: list[str] = []
    for char in norm:
        category = unicodedata.category(char)
        if category in ("Cf", "Mn", "Me"):
            continue
        out.append(" " if category == "Cc" and char not in "\t\n\r" else char)
    return "".join(out)


def _is_number_char(char: str) -> bool:
    """Any character that is, or stands for, a number (a letter, a symbol like KEYCAP TEN, or a
    digit of another script too)."""
    category = unicodedata.category(char)
    if category.startswith("N") or unicodedata.numeric(char, None) is not None:
        return True
    if category == "So":
        name = unicodedata.name(char, "")
        return "DIGIT" in name or "KEYCAP" in name
    return False


_PIECES = tuple(sorted(
    {*_ONES, *_TENS, *_SCALES, *_ORDINALS, *_SINGLES, *_PLURALS, "hundred"}, key=len, reverse=True
))  # fmt: skip


def _glued(word: str) -> bool:
    """Whether ``word`` is made whole of two or more number words run together."""
    reach = [-1] * (len(word) + 1)
    reach[0] = 0
    for i in range(len(word)):
        if reach[i] < 0:
            continue
        for piece in _PIECES:
            if word.startswith(piece, i):
                end = i + len(piece)
                reach[end] = max(reach[end], reach[i] + 1)
    return reach[-1] >= 2


def _opaque(word: str) -> bool:
    """A word that is, or hides, a number this module does not read exactly."""
    low = word.lower()
    if low in MULTIPLIERS or low.endswith(_MULTIPLIER_ENDS):
        return True
    if len(word) >= 2 and _ROMAN_ANY.fullmatch(word) and word.upper() not in ACRONYMS:
        return True
    return _glued(low)


def unreadable(text: str) -> list[str]:
    """The tokens of ``text`` that write a number this module does not read exactly (see the
    module docstring: it fails closed). Empty when there are none."""
    norm = unicodedata.normalize("NFKC", text)
    refused = [c for c in norm if not "0" <= c <= "9" and _is_number_char(c)]
    seen = _visible(norm)
    refused += [m.group() for m in _COMMA_RUN.finditer(seen) if not _GROUPING.fullmatch(m.group())]
    refused += [m.group() for m in _AFTER_NUMBER.finditer(seen)]
    refused += [word for word in _LETTERS.findall(seen) if _opaque(word)]
    return refused


@dataclass
class Allowed:
    """The numbers of a report's input: each value with the units it was seen with (``None``: a
    plain count), and the times, dates and dotted numbers as written."""

    units: dict[Fraction, set[str | None]] = field(default_factory=dict)
    exact: set[str] = field(default_factory=set)

    def add_value(self, value: Fraction | int | float | str, unit: str | None = None) -> None:
        self.units.setdefault(Fraction(value if not isinstance(value, float) else str(value)),
                              set()).add(unit)  # fmt: skip

    def add_text(self, text: str) -> None:
        """Every number ``text`` itself writes (a label, a date, a time, a definition)."""
        for item in numbers_of(text):
            for need in item.needs:
                for value in need:
                    self.units.setdefault(value, set()).add(item.unit)
            self.exact |= item.exact
            self.exact |= {f"--{e[5:10]}" for e in item.exact if _ISO_DATE.fullmatch(e)}

    def add_texts(self, texts: Iterable[str]) -> None:
        for text in texts:
            self.add_text(text)

    def holds(self, item: Found) -> bool:
        for need in item.needs:
            if not any(self._has(v, item.unit) for v in need):
                return False
        return not item.exact or bool(item.exact & self.exact)

    def _has(self, value: Fraction, unit: str | None) -> bool:
        seen = self.units.get(value)
        return seen is not None and unit in seen


def allowed_from(
    values: Iterable[tuple[int | float | str, str | None]] = (), texts: Iterable[str] = ()
) -> Allowed:
    """The numbers of an input: its (value, unit) pairs and the texts it writes."""
    allowed = Allowed()
    for value, unit in values:
        allowed.add_value(value, unit)
    allowed.add_texts(texts)
    return allowed


def unknown(prose: str, allowed: Allowed) -> list[Found]:
    """What ``prose`` writes as a number that ``allowed`` (the input's numbers) does not hold,
    first the tokens it cannot read at all (:func:`unreadable`), then the numbers it claims."""
    refused = [Found("unreadable", raw, (_need(NEVER),)) for raw in unreadable(prose)]
    return refused + [item for item in numbers_of(prose) if not allowed.holds(item)]


def check(prose: str, allowed: Allowed) -> bool:
    """True when every number of ``prose`` is in the input."""
    return not unknown(prose, allowed)
