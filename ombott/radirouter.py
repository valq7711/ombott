import re
from enum import IntEnum
from .radidict import RadiDict, DATA, HOOKS
from .helpers import OmbottException


###############################################################################
# Routing ######################################################################
###############################################################################


class RouteError(OmbottException):
    """ This is a base class for all routing related exceptions """

    def __init__(self, *args, **kw):
        super().__init__(*args)
        self.extra = kw


class RouteSyntaxError(RouteError):
    """ The route parser found something not supported by this router. """


class RouteBuildError(RouteError):
    """ The route could not be built. """


class RouteMethodError(RouteError):
    """ Method not allowed """


class RouteFilterExhaust:
    __slots__ = ('value', 'move_len', 'selector')
    def __init__(self, value, move_len, selector = None):
        self.value = value
        self.move_len = move_len
        self.selector = selector

    def get(self):
        return self.value, self.move_len, self.selector


def rex(conf):
    def f_in(matched, re_obj):
        for selector, v in enumerate(re_obj.groups()):
            if v is not None:
                selector += 1
                break
        else:
            selector = None
            v = matched
        return RouteFilterExhaust(v, re_obj.end(), selector)
    return conf, f_in, None


class FilterFactory:
    filters = {
        're':    lambda conf: (conf, None, None),
        'rex':   rex,
        'int':   lambda conf: (r'-?\d+', int, lambda x: str(int(x))),
        'float': lambda conf: (r'-?\d+(\.\d+)?', float, lambda x: str(float(x))),
        'path':  lambda conf: (f'.+(?={re.escape(conf)})' if conf else '.+$', None, None)
    }
    _filter_cache = {}

    @classmethod
    def make_filter(cls, filter:str, args:str):
        if not filter:
            return None
        fkey = f'{filter}({args})'

        if (handler := cls._filter_cache.get(fkey)):
            return handler

        mask, f_in, f_out = cls.filters[filter](args)
        mask = re.compile(mask)
        if f_in:
            if (
                (code := getattr(f_in, '__code__', None))
                and code.co_argcount != 1
            ):  # 0 means f_in(*args)
                def handler(param):
                    selector = None
                    if not (tmp := mask.match(param)):
                        return None, 0, selector
                    ret = f_in(tmp.group(), tmp)
                    if isinstance(ret, RouteFilterExhaust):
                        ret, pos, selector = ret.get()
                    else:
                        pos = tmp.end()
                    return ret, pos, selector
            else:
                def handler(param):
                    if not (tmp := mask.match(param)):
                        return None, 0, None
                    return f_in(tmp.group()), tmp.end(), None
        else:
            def handler(param):
                if not (tmp := mask.match(param)):
                    return None, 0, None
                return tmp.group(), tmp.end(), None
        cls._filter_cache[fkey] = handler
        return handler


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
        if (tmp := re.match(rex_str, s[i:])):
            j = i + tmp.end()
            ret = s[i:j] if group is None else tmp.group(group)
            self._set_pos(j)
        return ret

    def expect(self, rex_str, group = None):
        ret = self.eat(rex_str, group)
        if ret is None:
            raise RouteSyntaxError(
                f'Expected `{rex_str}` instead of `...{self.rest()}`\n\tin {self.s}'
            )
        return ret

    def expect_parenthesized(self):
        pos = find_pos_after_close_paren(self.s, self.pos, self.L)
        if pos is None:
            raise RouteSyntaxError(
                f'Missing closing parenthesis for `{self.current}` in `...{self.rest()}`\n\tin {self.s}'
            )
        ret = self.s[self.pos: pos]
        self._set_pos(pos)
        return ret

    def rest(self):
        return self.s[self.pos:]


class RouteMethod:
    __slots__ = ('route', 'name', 'handler', 'meta')

    def __init__(self, route, name, handler, meta = None):
        self.route = route
        self.name = name
        self.handler = handler
        self.meta = meta

    @classmethod
    def get_undecorated_callback(cls, func):
        ''' Return the callback. If the callback is a decorated function, try to
            recover the original function. '''
        if not (func := getattr(func, '__func__', None)):
            return func
        while (closure := getattr(func, '__closure__', None)):
            func = closure[0].cell_contents
        return func

    def __str__(self):
        cb = self.get_undecorated_callback(self.handler)
        return '{}: {}'.format(self.name, cb)

    def __repr__(self):
        cb = self.get_undecorated_callback(self.handler)
        return '<{}:{} {}>'.format(self.route.rule, self.name, cb)

    def __call__(self, *a, **kw):
        return self.handler(*a, **kw)


class Route:
    __slots__ = ('rule', '_methods', 'pattern', 'params', 'filters')

    param_delimiters = '{<'
    param_delimiters_map = {
        '<': '>',
        '{': '}'
    }
    anon_prefix = 'anon-'

    make_filter = staticmethod(FilterFactory.make_filter)

    def __init__(self, rule):
        #: The path-rule string (e.g. ``/wiki/:page``).
        self.rule = rule
        #: The HTTP methods dict like {'GET': {'handler': <callable>, 'meta': <any>} }
        self._methods = dict()
        pattern, params, filters = self.__class__.parse_rule(rule)
        self.pattern = pattern  # never starts from '/'
        self.params = params
        self.filters = filters

    def _set_methods(self, methods, handler, meta=None):
        for meth in methods:
            self._methods[meth] = RouteMethod(self, meth, handler, meta)

    def set_method(self, method, handler, meta=None):
        if isinstance(method, str):
            method = [method]
        self._set_methods(method, handler, meta)

    def _raise_if_registred(self, method):
        registred = set(self._methods) & set(method)
        if registred:
            raise RouteMethodError(
                f'Handler is already registred for `{list(registred)}`'
            )

    def add_method(self, method, *a, **kw):
        if isinstance(method, str):
            method = [method]
        self._raise_if_registred(method)
        self._set_methods(method, *a, **kw)

    def remove_method(self, method):
        if isinstance(method, str):
            method = [method]
        [self._methods.pop(m, None) for m in method]

    @property
    def methods(self):
        return dict(self._methods)

    def __getitem__(self, method):
        if isinstance(method, str):
            method = [method]
        for name in method:
            if (meth := self._methods.get(name)):
                return meth
        raise RouteMethodError()

    def params_signature(self):
        return {name: [False, filter] for name, filter in zip(self.params, self.filters)}

    def __call__(self, method, *a, **kw):
        return self[method](*a, **kw)

    def __repr__(self):
        return '<%r {%s}>' % (
            self.rule, ', '.join([str(m) for m in self.methods.values()])
        )

    @classmethod
    def make_params_dict(cls, names, values):
        return {n: v for n, v in zip(names, values) if not n.startswith(cls.anon_prefix)}

    @classmethod
    def parse_rule_iter(cls, rule):
        '''
        valid examples:
            `/abc/:some/foo` - simple param (param name matches all from `:` to `/`)
            `/abc/<some>other/foo` - simple param (param name matches all from `:` to `/`)
            `/abc/<param.path()>baz/foo` - matches `/abc/a/b/cbaz/foo`, param is `a/b/c`
            `/abc/<param.rex((foo)|(bar)|(baz))[1]>/foo` - matches `/abc/foobaz/foo`, param is `foo`
            `/abc/<param.rex((foo)|(bar)|(baz))[2]>baz/foo`   - matches `/abc/barbaz/foo`, param is  `bar`
            `/abc/<rex((foo)|(bar)|(baz))[3]>baz/foo`   - matches `/abc/bazbaz/foo`
        '''

        S = SymStream(rule)

        def parse_param():
            is_bottle_filter = False
            param, filter, filter_args, filter_selector = [None] * 4
            py_name = r'[a-zA-Z_]\w*'
            first = S.current

            if first == ':':
                S.next()  # eat ':'
                if S.current is not None:
                    param = S.expect(fr'({py_name})?((?=/)|$)', group = 1) or None
            else:
                assert first in cls.param_delimiters
                dclose = cls.param_delimiters_map[first]
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

        param_tokens = cls.param_delimiters + ':'
        while S.current:
            part, param, filter, filter_args, filter_selector = (None,) * 5
            # param logic
            if S.current in param_tokens:
                param, filter, filter_args, filter_selector = parse_param()
                # path needs special processing
                if filter == 'path':
                    tail = S.rest()
                    token_pos = tmp.end() if (tmp := re.match(fr'[^{param_tokens}]+', tail)) else len(tail)
                    filter_args = tail[: token_pos]
            # static logic
            else:
                part = S.eat(fr'[^{param_tokens}]+')

            yield part, param, filter, filter_args, filter_selector

    @classmethod
    def parse_rule(cls, rule):
        assert rule[0] == '/'
        rule = rule[1:]
        ret = []
        params = []
        filters = []
        anon_counter = 0
        for part, param, filter, filter_args, filter_selector in cls.parse_rule_iter(rule):
            if not part:  # it is param or/and filter
                part = '\r'
                if not param:
                    param = f'{cls.anon_prefix}{anon_counter}'
                    anon_counter += 1
                params.append(param)
                filters.append(cls.make_filter(filter, filter_args))
                if filter_selector:
                    part += filter_selector
            ret.append(part)
        # return '/'.join(ret), params, filters
        return ''.join(ret), params, filters


class HookTypes(IntEnum):
    SIMPLE = 0
    PARTIAL = 1


class RadiRouter:

    __slots__ = ('radidict', 'routes', 'hooks', 'named_routes')

    parse_rule = staticmethod(Route.parse_rule)

    def __init__(self):
        self.radidict = RadiDict()
        self.routes = dict()
        self.hooks = dict()
        self.named_routes = dict()

    @classmethod
    def to_pattern(cls, rule):
        return cls.parse_rule(rule)[0]

    def match(self, rule = None, filters = None, *, route_pattern = None, get_hooks = False):
        '''
        try to find the registered route, if filters is passed - performs filters comparision
        match('/foo/:bar:re([^/]+)/baz') - will parse route and retrieve filters
        match( 'foo/\r/baz', [make_filter('re', '[^/]+')] ) - the same as above
        match(pattern, filters)  - is the same as -  match(filters, route_pattern = pattern)
        match(route_pattern = '/foo/\r/baz') - without filter comparision - used for remove, hook installation and general info
        '''

        if route_pattern is None:
            if filters is None:
                route_pattern, params, filters = self.parse_rule(rule)
            else:
                # if `filters` is passed, but not `route_pattern`, then rule is pattern
                route_pattern = rule
        if route_pattern:
            assert route_pattern[0] != '/'
        node, mismatch, i, param_idx, stack = self.radidict._match(route_pattern, param_filters = filters)
        if not mismatch:
            return node[DATA] if not get_hooks else node[HOOKS]

    def add(self, rule, methods, handler, name=None, *, meta=None, overwrite=False):
        if isinstance(methods, str):
            methods = [methods]
        methods = [_.upper() for _ in methods]
        return self._add(rule, methods, handler, name, meta=meta, overwrite=overwrite)

    def _add(self, rule, methods, handler, name=None, *, meta=None, overwrite=False):
        route = Route(rule)
        if (route_ := self.match(route.pattern, route.filters)):
            route = route_
        else:
            self.radidict.add(route.pattern, route, route.params_signature())
            self.routes[route.pattern] = route

        if overwrite:
            route.set_method(methods, handler, meta)
        else:
            route.add_method(methods, handler, meta)

        if name:
            registred = self.named_routes.get(name)
            if not overwrite and registred and registred and registred is not route:
                raise RouteBuildError(f'Can`t register route, name `{name}` is already used')
            self.named_routes[name] = route
        return route

    @staticmethod
    def hook_installer(route_hooks, hook, hook_type=HookTypes.SIMPLE):
        hook_type = HookTypes(hook_type)
        if not route_hooks:
            route_hooks = [None, None]
        route_hooks[hook_type] = hook
        return route_hooks

    def add_hook(self, rule, *args, **kwargs):
        route_pattern, params, filters = self.parse_rule(rule)
        route_hooks = self.match(route_pattern = route_pattern, get_hooks = True)
        new_route_hooks = self.hook_installer(route_hooks, *args, **kwargs)
        if new_route_hooks is not None and new_route_hooks is not route_hooks:
            params = {name: [False, filter] for name, filter in zip(params, filters)}
            self.radidict.add_hooks(route_pattern, new_route_hooks, params)
            self.hooks[route_pattern] = new_route_hooks
        return route_pattern

    def get_hook(self, rule):
        route_pattern, params, filters = self.parse_rule(rule)
        return self.hooks[route_pattern]

    def remove_hook(self, rule):
        route_pattern = self.to_pattern(rule)
        self.radidict.remove(route_pattern, hooks_only=True)
        self.hooks.pop(route_pattern, None)

    def get(self, path, methods):
        '''
        returns a tuple of  (route:Route, error:[code, reason, *extra])
        ignores start/end slashes
        '''
        path = path.strip('/')
        route, extra = self.radidict.get(path, allow_partial=True)
        if not route:
            return None, [404, 'Not Found', extra]
        try:
            meth = route[methods]
            params = route.make_params_dict(extra['param_keys'], extra['param_values'])
            return [meth, params, extra['hooks']], None
        except RouteMethodError:
            allowed = ",".join(sorted(route.methods.keys()))
        return None, [405, "Method not allowed.", allowed]

    def remove(self, route = None, *, route_pattern = None, name = None):
        """
        use '*' to remove whole route-branch
        remove('/foo/bar/*') - remove all routes starts with `/foo/bar/`
        `/` - doesnt matter, so you can
        remove('/foo/ba*') - remove all routes starts with `/foo/ba`
        """
        if route is not None:
            if isinstance(route, str):
                route_pattern = self.to_pattern(route)
                route = None
            else:
                route_pattern = route.pattern
        elif name is not None:
            route = self.named_routes[name]
            route_pattern = route.pattern

        self.radidict.remove(route_pattern)
        if route:
            del self.routes[route.pattern]
        else:
            if route_pattern[-1] == '*':
                route_pattern = route_pattern[:-1]
                patterns_to_del = [
                    pattern for pattern in self.routes
                    if pattern.startswith(route_pattern)
                ]
                [self.routes.pop(pattern) for pattern in patterns_to_del]
            else:
                del self.routes[route_pattern]

    def __getitem__(self, k):
        return self.named_routes.get(k)
