import re


class _RouteFilterExhaust:
    __slots__ = ('value', 'move_len', 'selector')

    def __init__(self, value, move_len, selector = None):
        self.value = value
        self.move_len = move_len
        self.selector = selector

    def get(self):
        return self.value, self.move_len, self.selector


def _rex(conf):
    def f_in(matched, re_obj):
        for selector, v in enumerate(re_obj.groups()):
            if v is not None:
                selector += 1
                break
        else:
            selector = None
            v = matched
        return _RouteFilterExhaust(v, re_obj.end(), selector)
    return conf, f_in, None


class FilterFactory:
    filters = {
        're':    lambda conf: (conf, None, None),
        'rex':   _rex,
        'int':   lambda conf: (r'-?\d+', int, lambda x: str(int(x))),
        'float': lambda conf: (r'-?\d+(\.\d+)?', float, lambda x: str(float(x))),
        'path':  lambda conf: (f'.+(?={re.escape(conf)})' if conf else '.+$', None, None)
    }
    _filter_cache = {}

    @classmethod
    def make_filter(cls, filter: str, args: str):
        if not filter:
            return None, None
        fkey = f'{filter}({args})'

        handler_f_out = cls._filter_cache.get(fkey)
        if handler_f_out:
            return handler_f_out

        mask, f_in, f_out = cls.filters[filter](args)
        mask = re.compile(mask)
        if f_in:
            code = getattr(f_in, '__code__', None)
            if code and code.co_argcount != 1:  # 0 means f_in(*args)
                def handler(param):
                    selector = None
                    tmp = mask.match(param)
                    if not tmp:
                        return None, 0, selector
                    ret = f_in(tmp.group(), tmp)
                    if isinstance(ret, _RouteFilterExhaust):
                        ret, pos, selector = ret.get()
                    else:
                        pos = tmp.end()
                    return ret, pos, selector
            else:
                def handler(param):
                    tmp = mask.match(param)
                    if not tmp:
                        return None, 0, None
                    return f_in(tmp.group()), tmp.end(), None
        else:
            def handler(param):
                tmp = mask.match(param)
                if not tmp:
                    return None, 0, None
                return tmp.group(), tmp.end(), None
        cls._filter_cache[fkey] = [handler, f_out]
        return handler, f_out
