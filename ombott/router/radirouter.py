from enum import IntEnum
from .radidict import RadiDict, DATA, HOOKS
from .filter_factory import FilterFactory
from .errors import RouteBuildError, RouteMethodError
from .parser import Parser


class RouteMethod:
    __slots__ = ('route', 'name', 'handler', 'meta')

    def __init__(self, route, name, handler, meta=None):
        self.route = route
        self.name = name
        self.handler = handler
        self.meta = meta

    def remove(self):
        self.route.remove_method(self.name)

    @classmethod
    def get_func_fullname(cls, func):
        return f'{func.__module__}.{func.__qualname__}'

    @property
    def handler_fullname(self):
        return self.get_func_fullname(self.handler)

    def __str__(self):
        return '{}: {}'.format(self.name, self.handler)

    def __repr__(self):
        return '<{}:{} {}>'.format(self.route.rule, self.name, self.handler)

    def __call__(self, *a, **kw):
        return self.handler(*a, **kw)


class Route:
    __slots__ = (
        'rule', '_methods', 'pattern', 'params', 'filters',
        'pattern_out', 'filters_out'
    )

    parser = Parser()

    anon_prefix = 'anon-'

    make_filter = staticmethod(FilterFactory.make_filter)

    def __init__(self, rule):
        #: The path-rule string (e.g. ``/wiki/:page``).
        self.rule = rule
        #: The HTTP methods dict like {'GET': {'handler': <callable>, 'meta': <any>} }
        self._methods = dict()
        pattern, params, filters, pattern_out, filters_out = self.__class__.parse_rule(rule)
        self.pattern = pattern  # never starts from '/'
        self.params = params
        self.filters = filters

        self.pattern_out = pattern_out
        self.filters_out = filters_out

    def url(self, *args, **kw):

        params = self.params
        if not params:
            return self.pattern_out

        filters = self.filters
        filters_out = self.filters_out
        anon_prefix = self.anon_prefix
        pattern_out = self.pattern_out

        ret = []
        pidx = 0
        args_idx = 0
        cidx = 0
        clen = 0
        end = 0
        for c in pattern_out:
            if c != '\r':
                clen += 1
                continue
            end = cidx
            if clen:
                end += clen
                clen = 0
                ret.append(pattern_out[cidx:end])
            cidx = end + 1

            pname = params[pidx]
            f_out = filters_out[pidx]
            f_in = filters[pidx]
            pidx += 1

            if pname.startswith(anon_prefix):
                prt = args[args_idx]
                args_idx += 1
            else:
                prt = kw[pname]
            if f_out:
                prt = f_out(prt)
            if f_in:
                assert f_in(prt)[1]  # `pos` must be > 0 if match
            ret.append(prt)

        if clen:
            end = cidx + clen
            ret.append(pattern_out[cidx:end])

        return ''.join(ret)

    def _set_methods(self, methods, handler, meta=None):
        for meth in methods:
            self._methods[meth] = RouteMethod(self, meth, handler, meta)

    def set_method(self, method, handler, meta=None):
        if isinstance(method, str):
            method = [method]
        self._set_methods(method, handler, meta)

    def _raise_if_registered(self, method, candidate):
        registered = set(self._methods) & set(method)
        if registered:
            registered_fullnames = {
                m: self._methods[m].handler_fullname
                for m in registered
            }
            candidate_fullname = RouteMethod.get_func_fullname(candidate)
            raise RouteMethodError(
                f'Trying to register `{candidate_fullname}` '
                f'as handler for route methods `{self.rule}: {method}`, '
                f'but there are already registered: `{registered_fullnames}`'
            )

    def add_method(self, method, handler, meta=None):
        if isinstance(method, str):
            method = [method]
        self._raise_if_registered(method, handler)
        self._set_methods(method, handler, meta)

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
            meth = self._methods.get(name)
            if meth:
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
    def parse_rule(cls, rule):
        assert rule[0] == '/'
        rule = rule[1:]
        pattern = []
        pattern_out = []  # to build url (pattern without filter selectors)
        params = []
        filters = []
        filters_out = []
        anon_counter = 0
        for part, param, filter, filter_args, filter_selector in cls.parser.iter_parse(rule):
            filter_selector = filter_selector or ''
            if not part:  # it is param or/and filter
                part = '\r'
                if not param:
                    param = f'{cls.anon_prefix}{anon_counter}'
                    anon_counter += 1
                params.append(param)
                h, f_out = cls.make_filter(filter, filter_args)
                filters.append(h)
                filters_out.append(f_out)
            pattern.append(part + filter_selector)
            pattern_out.append(part)
        return ''.join(pattern), params, filters, ''.join(pattern_out), filters_out


class HookTypes(IntEnum):
    SIMPLE = 0
    PARTIAL = 1


class RouteKey(dict):
    @staticmethod
    def check_args(args):
        if len(args) > 1:
            raise TypeError('Expected `rule` or `pattern`, not both')

    def __init__(self, rule=None, *, pattern=None):
        self.check_args([a for a in [rule, pattern] if a is not None])
        if rule:
            super().__init__(rule=rule)
        else:
            super().__init__(pattern=pattern)


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

    def add(self, rule, methods, handler, name=None, *, meta=None, overwrite=False):
        if isinstance(methods, str):
            methods = [methods]
        methods = [_.upper() for _ in methods]
        return self._add(rule, methods, handler, name, meta=meta, overwrite=overwrite)

    def __getitem__(self, key):
        """Return route object by the name or rule or pattern.

        `key` treatment by type:
            `str` - name of the named route
            `set` - rule (must be single-item)
            `dict` - rule or pattern (must be single-item)

        """
        if isinstance(key, str):
            return self.named_routes.get(key)

        RouteKey.check_args(key)
        if isinstance(key, set):
            kwargs = dict(rule=[*key][0])
        elif isinstance(key, dict):
            kwargs = key.copy()
            if ('pattern' in kwargs):
                kwargs['route_pattern'] = kwargs.pop('pattern')
        else:
            raise TypeError('Item key must be instance of (str | set | dict)')
        return self._match(**kwargs)

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
            route = self.named_routes.pop(name)
            route_pattern = route.pattern

        self.radidict.remove(route_pattern)
        if route:
            del self.routes[route.pattern]
        else:
            if route_pattern.endswith('*'):
                route_pattern = route_pattern[:-1]
                patterns_to_del = [
                    pattern for pattern in self.routes
                    if pattern.startswith(route_pattern)
                ]
                [self.routes.pop(pattern) for pattern in patterns_to_del]
                self._remove_named_routers(set(patterns_to_del))
            else:
                self.routes.pop(route_pattern, None)
                self._remove_named_routers({route_pattern})

    def resolve(self, path, methods=None):
        """
        if `methods` passed, return a tuple of (end_point, err404_405):
                - end_point: [route_meth: RouteMethod, params: dict, hooks: list] | None
                - error: [code: int, reason: str, extra] | None
        else:
            return route: Route or None

        NOTE: ignores start/end slashes

        """
        path = path.strip('/')
        route, extra = self.radidict.get(path, allow_partial=True)

        if not methods:
            return route or None

        if not route:
            return None, [404, 'Not Found', extra]
        try:
            meth = route[methods]
            params = route.make_params_dict(extra['param_keys'], extra['param_values'])
            return [meth, params, extra['hooks']], None
        except RouteMethodError:
            allowed = ",".join(sorted(route.methods))
        return None, [405, "Method not allowed.", allowed]

    @staticmethod
    def hook_installer(route_hooks, hook, hook_type=HookTypes.SIMPLE):
        hook_type = HookTypes(hook_type)
        if not route_hooks:
            route_hooks = [None, None]
        route_hooks[hook_type] = hook
        return route_hooks

    def add_hook(self, rule, *args, **kwargs):
        route_pattern, params, filters, _, _ = self.parse_rule(rule)
        route_hooks = self._match(route_pattern = route_pattern, get_hooks = True)
        new_route_hooks = self.hook_installer(route_hooks, *args, **kwargs)
        if new_route_hooks is not None and new_route_hooks is not route_hooks:
            params = {name: [False, filter] for name, filter in zip(params, filters)}
            self.radidict.add_hooks(route_pattern, new_route_hooks, params)
            self.hooks[route_pattern] = new_route_hooks
        return route_pattern

    def get_hook(self, rule):
        route_pattern, params, filters, _, _ = self.parse_rule(rule)
        return self.hooks[route_pattern]

    def remove_hook(self, rule):
        route_pattern = self.to_pattern(rule)
        self.radidict.remove(route_pattern, hooks_only=True)
        self.hooks.pop(route_pattern, None)

    def _match(self, rule = None, filters = None, *, route_pattern = None, get_hooks = False):
        '''
        try to find the registered route, if filters is passed - performs filters comparision
        _match('/foo/:bar:re([^/]+)/baz') - will parse route and retrieve filters
        _match( 'foo/\r/baz', [make_filter('re', '[^/]+')] ) - the same as above
        _match(pattern, filters)  - is the same as -  _match(filters, route_pattern = pattern)
        _match(route_pattern = '/foo/\r/baz') - without filter comparision
            - used for removing, hook installation and general info
        '''

        if route_pattern is None:
            if filters is None:
                route_pattern, params, filters, _, _ = self.parse_rule(rule)
            else:
                # if `filters` is passed, but not `route_pattern`, then rule is pattern
                route_pattern = rule
        if route_pattern:
            assert route_pattern[0] != '/'
        node, mismatch, i, param_idx, stack = self.radidict._match(route_pattern, param_filters = filters)
        if not mismatch:
            return node[DATA] if not get_hooks else node[HOOKS]

    def _add(self, rule, methods, handler, name=None, *, meta=None, overwrite=False):
        route = Route(rule)
        route_ = self._match(route.pattern, route.filters)
        if route_:
            route = route_
        else:
            self.radidict.add(route.pattern, route, route.params_signature())
            self.routes[route.pattern] = route

        if overwrite:
            route.set_method(methods, handler, meta)
        else:
            route.add_method(methods, handler, meta)

        if name:
            registered = self.named_routes.get(name)
            if not overwrite and registered and registered is not route:
                raise RouteBuildError(f'Can`t register route, name `{name}` is already used')
            self.named_routes[name] = route
        return route

    def _remove_named_routers(self, pattern_set):
        for k, r in [*self.named_routes.items()]:
            if r.pattern in pattern_set:
                self.named_routes.pop(k)
