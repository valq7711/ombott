import re

from .sym_stream import SymStream
from .errors import RouteSyntaxError

class Parser:
    param_delimiters = '{<'
    param_delimiters_map = {
        '<': '>',
        '{': '}'
    }

    def __init__(self):
        self._stream = None
        self._rule = None

    def iter_parse(self, rule):
        self._rule = rule
        self._stream = SymStream(rule)
        yield from self._iter_parse()
        self._rule = None
        self._stream = None

    def _iter_parse(self):
        '''
        valid examples:
            `/abc/:some/foo` - simple param (param name matches all from `:` to `/`)
            `/abc/<some>other/foo` - simple param (param name matches all from `:` to `/`)
            `/abc/<param.path()>baz/foo` - matches `/abc/a/b/cbaz/foo`, param is `a/b/c`
            `/abc/<param.rex((foo)|(bar)|(baz))[1]>/foo` - matches `/abc/foobaz/foo`, param is `foo`
            `/abc/<param.rex((foo)|(bar)|(baz))[2]>baz/foo`   - matches `/abc/barbaz/foo`, param is  `bar`
            `/abc/<rex((foo)|(bar)|(baz))[3]>baz/foo`   - matches `/abc/bazbaz/foo`
        '''

        S = self._stream

        param_tokens = self.param_delimiters + ':'
        while S.current:
            part, param, filter, filter_args, filter_selector = (None,) * 5
            # param logic
            if S.current in param_tokens:
                param, filter, filter_args, filter_selector = self._parse_param()
                # path needs special processing
                if filter == 'path':
                    tail = S.rest()
                    token_pos = tmp.end() if (tmp := re.match(fr'[^{param_tokens}]+', tail)) else len(tail)
                    filter_args = tail[: token_pos]
            # static logic
            else:
                part = S.eat(fr'[^{param_tokens}]+')

            yield part, param, filter, filter_args, filter_selector

    def _parse_param(self):
        S = self._stream
        rule = self._rule

        is_bottle_filter = False
        param, filter, filter_args, filter_selector = (None,) * 4
        py_name = r'[a-zA-Z_]\w*'
        first = S.current

        if first == ':':
            S.next()  # eat ':'
            if S.current is not None:
                param = S.expect(fr'({py_name})?((?=/)|$)', group = 1) or None
        else:
            assert first in self.param_delimiters
            dclose = self.param_delimiters_map[first]
            S.next()  # eat open-delimiter
            if S.current == ':':  # bottle styled filter
                S.next()
                is_bottle_filter = True

            name = S.expect(fr'{py_name}')
            if is_bottle_filter:
                filter = name

            if S.current == dclose:
                if not filter:
                    param = name
            elif S.current == '.':
                S.next()  # eat '.' or ':'
                param = name
                filter = S.expect(fr'{py_name}')
            elif S.current == ':':
                if not filter:
                    S.next()  # eat '.' or ':'
                    param = name
                    filter = S.expect(fr'{py_name}')
            elif S.current == '(':
                if not filter:
                    filter = name
            else:
                raise RouteSyntaxError(
                    f'Unexpected syntax in `...{S.rest()}`\n\tin {rule}'
                )

            if filter:
                if S.current not in f':({dclose}':
                    raise RouteSyntaxError(
                        f'Expected one of `(,:,>` after filter instead of `...{S.rest()}`\n\tin {rule}'
                    )
                if S.current != dclose:
                    if S.current == '(':
                        filter_args = S.expect_parenthesized()[1:-1]
                        if S.current == '[':
                            filter_selector = S.expect(r'\[(.+?)\]', 1)
                            if not filter_selector:
                                raise RouteSyntaxError(
                                    f'filter selector value was expected instead of `...{S.rest()}`\n\tin {rule}'
                                )
                    else:  # bottle style
                        S.next()
                        filter_args = S.eat(fr'[^{dclose}]+')
            S.expect(dclose)
        return param, filter, filter_args, filter_selector
