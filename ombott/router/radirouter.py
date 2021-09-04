from enum import IntEnum
from .radidict import RadiDict, DATA, HOOKS
from .filter_factory import FilterFactory
from .errors import RouteBuildError, RouteMethodError
from .parser import Parser

###############################################################################
# Routing ######################################################################
###############################################################################


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
        func = getattr(func, '__func__', None)
        if not func:
            return func
        closure = getattr(func, '__closure__', None)
        while closure:
            func = closure[0].cell_contents
            closure = getattr(func, '__closure__', None)
        return func

    def remove(self):
        self.route.remove_method(self.name)

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

    parser = Parser()

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
        ret = []
        params = []
        filters = []
        anon_counter = 0
        for part, param, filter, filter_args, filter_selector in cls.parser.iter_parse(rule):
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
        return ''.join(ret), params, filters


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
        route_pattern, params, filters = self.parse_rule(rule)
        route_hooks = self._match(route_pattern = route_pattern, get_hooks = True)
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

    def _match(self, rule = None, filters = None, *, route_pattern = None, get_hooks = False):
        '''
        try to find the registered route, if filters is passed - performs filters comparision
        _match('/foo/:bar:re([^/]+)/baz') - will parse route and retrieve filters
        _match( 'foo/\r/baz', [make_filter('re', '[^/]+')] ) - the same as above
        _match(pattern, filters)  - is the same as -  _match(filters, route_pattern = pattern)
        _match(route_pattern = '/foo/\r/baz') - without filter comparision - used for remove, hook installation and general info
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
            registred = self.named_routes.get(name)
            if not overwrite and registred and registred and registred is not route:
                raise RouteBuildError(f'Can`t register route, name `{name}` is already used')
            self.named_routes[name] = route
        return route

    def _remove_named_routers(self, pattern_set):
        for k, r in [*self.named_routes.items()]:
            if r.pattern in pattern_set:
                self.named_routes.pop(k)


