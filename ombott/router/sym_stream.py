import re

from .errors import RouteSyntaxError


def find_pos_after_close_paren(s, start=0, length = None):
    map_close = {
        '(': ')',
        '{': '}',
        '<': '>',
    }
    open_ = s[start]
    close_ = map_close[open_]
    L = len(s[start:]) if length is None else length
    i = start + 1
    done = False
    nested_level = 0
    while i < L:
        if s[i] == '\\':
            i += 2
            continue
        if s[i] == close_:
            if nested_level > 0:
                nested_level -= 1
            else:
                i += 1
                done = True
                break
        elif s[i] == open_:
            nested_level += 1
        i += 1
    if not done:
        return None
    return i


class SymStream:
    syntax_error = RouteSyntaxError

    def __init__(self, s: str):
        self.s = s
        self.L = len(s)
        self.pos = 0
        self.current = s[0] if s else None

    def _set_pos(self, pos):
        if not self.current:
            return
        if pos < self.L:
            self.pos = pos
            self.current = self.s[pos]
        else:
            self.pos = self.L
            self.current = None

    def next(self):
        if not self.current:
            return None
        self._set_pos(self.pos + 1)
        return self.current

    def eat(self, rex_str, group = None):
        if not self.current:
            return None
        i = self.pos
        s = self.s
        ret = None
        tmp = re.match(rex_str, s[i:])
        if tmp:
            j = i + tmp.end()
            ret = s[i:j] if group is None else tmp.group(group)
            self._set_pos(j)
        return ret

    def expect(self, rex_str, group = None):
        ret = self.eat(rex_str, group)
        if ret is None:
            raise self.syntax_error(
                f'Expected `{rex_str}` instead of `...{self.rest()}`\n\tin {self.s}'
            )
        return ret

    def expect_parenthesized(self):
        pos = find_pos_after_close_paren(self.s, self.pos, self.L)
        if pos is None:
            raise self.syntax_error(
                f'Missing closing parenthesis for `{self.current}` in `...{self.rest()}`\n\tin {self.s}'
            )
        ret = self.s[self.pos: pos]
        self._set_pos(pos)
        return ret

    def rest(self):
        return self.s[self.pos:]
