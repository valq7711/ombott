from .radidict import RadiDict, DATA, HOOKS
from .helpers import OmbottException
import re


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
        'float': lambda conf: (r'-?[\d.]+', float, lambda x: str(float(x))),
        'path':  lambda conf: (f'.+?(?={re.escape(conf)})' if conf else '.+$', None, None)
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
            if (code := getattr(f_in, '__code__', None)) \
            and code.co_argcount != 1:  # 0 means f_in(*args)
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


class Route:
    ''' This class wraps a route callback along with route specific metadata and
        It is also responsible for turing an URL path rule into a regular expression usable by the Router.
    '''
    param_delimiters = '<,>'.split(',')
    make_filter = staticmethod(FilterFactory.make_filter)

    def __init__(self, rule, method, callback, name = None):
        #: The path-rule string (e.g. ``/wiki/:page``).
        self.rule = rule
        #: The HTTP method as a string (e.g. ``GET``).
        self.method = method
        #: The original callback with no plugins applied. Useful for introspection.
        self.callback = callback
        #: The name of the route (if specified) or ``None``.
        self.name = name or None

        pattern, params, filters = self.__class__.parse_route(rule)
        self.pattern = pattern
        self.params = params
        self.filters = filters

    def params_signature(self):
        return {name: [False, filter] for name, filter in zip(self.params, self.filters)}

    def __call__(self, *a, **ka):
        return self.callback(*a, **ka)

    def get_undecorated_callback(self):
        ''' Return the callback. If the callback is a decorated function, try to
            recover the original function. '''
        func = self.callback
        if not (func := getattr(func, '__func__', None)):
            return func
        while (closure := getattr(func, '__closure__', None)):
            func = closure[0].cell_contents
        return func

    def __repr__(self):
        cb = self.get_undecorated_callback()
        return '<%s %r %r>' % (self.method, self.rule, cb)

    @classmethod
    def parse_route_iter(cls, route):
        def eat(rex_str, group = None):
            nonlocal i
            ret = None
            if (tmp := re.match(rex_str, route[i:])):
                j = i + tmp.end()
                ret = route[i:j] if group is None else tmp.group(group)
                i = j
            return ret

        route = route.lstrip('/')
        i = 0
        L = len(route)
        dopen, dclose = cls.param_delimiters
        peek = lambda i: route[i] if i < L else None
        while i < L:
            part = None
            param = None
            filter = None
            filter_args = None
            filter_selector = None
            # param logic
            if peek(i) == dopen:
                i += 1  # eat `dopen`
                param = eat(f'[^:{dclose}]*')  # eat until `:` or `dclose`
                if peek(i) == ':':
                    i += 1  # eat `:`
                    filter = eat(f'[^:{dclose}]+')  # must exists
                    if peek(i) == ':':
                        i += 1  # eat `:`
                        # must exists, eat until `dclose/` or `dclose$`
                        filter_args = eat(f'.+?(?=({dclose}$)|({dclose}/))')
                i += 1  # eat `dclose`
            # alternative syntax like '/:param:filter(args)/' or '/:filter()/'
            elif peek(i) == ':':
                i += 1  # eat `:`
                param = eat('[^:.(/]*')  # eat until `:` or `/`
                if i < L:
                    if peek(i) in ':.':
                        i += 1  # eat `:`
                        filter = eat('[^(]+')  # must exists
                    elif peek(i) == '(':
                        filter = param
                        param = None
                    if peek(i) == '(':
                        i += 1  # eat `(`
                        # eat until `)[.+?]/` or `)/` or ')$' or `)[.+?]$`
                        filter_args = eat(r'.*?(?=(\)(/|$))|(\)\[\w+\](/|$)))')
                        if filter_args is None:
                            raise RouteSyntaxError(f'bad filter args syntax: ...{route[i:]}\n\tin {route}')
                        i += 1  # eat `)`
                        if peek(i) == '[':  # selector
                            filter_selector = eat(r'\[(.+?)\]', 1)
                            if not filter_selector:
                                raise RouteSyntaxError('filter selector value was expected')
                    elif filter:
                        raise RouteSyntaxError('filter must end with `()`')
            # static logic
            else:
                # part = eat(f'[^/:{dopen}]+')
                part = eat(f'[^:{dopen}]+')
            # path needs special processing
            if filter == 'path':
                tail = route[i:]
                token_pos = tmp.end() if (tmp := re.match(f'[^:{dopen}]+', tail)) else len(tail)
                filter_args = tail[: token_pos]
            # if peek(i) == '/':
            #    i+=1
            yield part, param, filter, filter_args, filter_selector

    @classmethod
    def parse_route(cls, route):
        # route_pattern
        ret = ['/'] if not route or route[0] == '/' else []
        params = []
        filters = []
        for part, param, filter, filter_args, filter_selector in cls.parse_route_iter(route):
            if not part:  # it is param or/and filter
                part = '\r'
                params.append(param)
                filters.append(cls.make_filter(filter, filter_args))
                if filter_selector:
                    part += filter_selector
            ret.append(part)
        # return '/'.join(ret), params, filters
        return ''.join(ret), params, filters


class RadiRouter:
    parse_route = staticmethod(Route.parse_route)

    def __init__(self):
        self.radidict = RadiDict()
        self.routes = []

    @classmethod
    def to_pattern(cls, route):
        return cls.parse_route(route)[0]

    def match(self, rule = None, filters = None, *, route_pattern = None, get_hooks = False):
        '''
        try to find the registered route, if filters is passed - performs filters comparision
        match('/foo/:bar:re([^/]+)/baz') - will parse route and retrieve filters
        match( '/foo/\r/baz', [make_filter('re', '[^/]+')] ) - the same as above
        match(pattern, filters)  - is the same as -  match(filters, route_pattern = pattern)
        match(route_pattern = '/foo/\r/baz') - without filter comparision - used for remove, hook installation and general info
        '''

        if route_pattern is None:
            if filters is None:
                route_pattern, params, filters = self.parse_route(rule)
            else:
                route_pattern = rule

        route_pattern = route_pattern.lstrip('/')
        node, mismatch, i, param_idx, stack = self.radidict._match(route_pattern, param_filters = filters)
        if not mismatch:
            return node[DATA] if not get_hooks else node[HOOKS]

    def add(self, rule, method, handler, name = None):
        if isinstance(method, str):
            method = [method.upper()]
        else:
            method = [_.upper() for _ in method]
        route = Route(rule, method, handler, name)
        end_point = self.match(route.pattern, route.filters)
        if end_point:
            common_meth = list(set(end_point) & set(method))
            if not common_meth:
                end_point.update(dict.fromkeys(method, route))
            else:
                raise RouteBuildError(f'handlers already registred for: {sorted(common_meth)}')
        else:
            end_point = dict.fromkeys(method, route)
            self.radidict.add(route.pattern.lstrip('/'), end_point, route.params_signature())
            self.routes.append(route)

    def add_hook(self, rule, hook):
        hooks = [hook] if not isinstance(hook, (list, tuple)) else hook
        route_pattern, params, filters = self.parse_route(rule)
        route_hooks = self.match(route_pattern = route_pattern, get_hooks = True)
        if route_hooks is not None:
            route_hooks.extend(hooks)
        else:
            params = {name: [False, filter] for name, filter in zip(params, filters)}
            self.radidict.add_hooks(route_pattern.lstrip('/'), hooks, params)

    def remove_hook(self, rule = None, hook = None, *, route_pattern = None):
        hooks = hook if isinstance(hook, (list, tuple)) else [hook]
        if rule is not None:
            route_pattern = self.to_pattern(rule)
        route_hooks = self.match(route_pattern = route_pattern, get_hooks = True)
        if route_hooks:
            route_hooks[:] = [h for h in route_hooks if h not in hooks]

    def get(self, route, methods):
        '''
        returns a tuple of  (route:Route, error:[code, reason, *extra])
        ignores start/end slashes
        '''

        if not (tmp := self.radidict.get(route.strip('/'))):
            return None, [404, 'Not Found']
        end_point, param_names, param_values, hooks = tmp
        for meth in methods:
            if (ret := end_point.get(meth)):
                return [ret, param_names, param_values, hooks], None
        allowed = ",".join(sorted(end_point))
        return None, [405, "Method not allowed.", allowed]

    def remove(self, rule = None, *, route_pattern = None):
        '''
        use '*' to remove whole route-branch
        remove('/foo/bar/*') - remove all routes starts with `/foo/bar/`
        `/` - doesnt matter, so you can
        remove('/foo/ba*') - remove all routes starts with `/foo/ba`
        '''

        if rule is not None:
            route_pattern = self.to_pattern(rule)
        self.radidict.remove(route_pattern.lstrip('/'))
        if route_pattern[-1] == '*':
            route_pattern = route_pattern[:-1]
            [self.routes.remove(r) for r in self.routes if r.pattern.startswith(route_pattern)]
        else:
            [self.routes.remove(r) for r in self.routes if r.pattern == route_pattern]
