"""Concrete index batches keep percent-encoded SDK paths below server limits."""
import re
from urllib.parse import quote


def index_batches(names, *, byte_budget=3000):
    if type(byte_budget) is not int or not 1 <= byte_budget <= 3000:
        raise ValueError('Invalid path budget')
    batch, length = [], 0
    seen = set()
    for name in names:
        if (not isinstance(name, str) or not name or len(name.encode('utf-8')) > 255
                or re.search(r'[,*/?\\#]', name)):
            raise ValueError('Invalid concrete index')
        if name in seen:
            continue
        seen.add(name)
        item_size = len(quote(name, safe=''))
        if item_size > byte_budget:
            raise ValueError('Concrete index exceeds path budget')
        size = item_size + (3 if batch else 0)
        if length + size > byte_budget:
            yield batch
            batch, length, size = [], 0, item_size
        batch.append(name)
        length += size
    if batch:
        yield batch
