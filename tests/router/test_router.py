import pytest
from ombott.router import RadiRouter, Route
from ombott.router.errors import RouteMethodError


route_meth_handler_path = [
    ('/foo/bar', 'GET', 'foo_bar:get', '/foo/bar'),
    ('/foo/bar', 'POST', 'foo_bar:post', '/foo/bar/'),
    ('/foo/bar', ['PUT', 'PATCH'], 'foo_bar:put,patch', 'foo/bar'),
    ('foo@/named/foo', ['PUT', 'PATCH'], 'foo@:put,patch', '/named/foo'),
    ('bar@/named/bar', ['PUT', 'PATCH'], 'bar@:put,patch', '/named/bar'),

    ('/foo/bar1', 'GET', 404, ['/foo/ba', '/foo/ba12']),
    ('/foo/bar1', 'POST', 405, '/foo/bar1:PATCH'),

    ('/foo/<re(pro.+?(?=l))>le/:user/bar', 'GET', dict(user='tom'), '/foo/profile/tom/bar'),
    ('/re/{re(to.)}/bar', 'GET', 're:get', '/re/tom/bar'),
    ('/re/{:re(to.)}/bar', 'PUT', 're:put', '/re/tom/bar'),
    ('/re/{name:re(to.)}/bar', 'POST', dict(name='tom'), '/re/tom/bar'),
    ('/re/{name:re(to.)}/bar1', 'GET', dict(name='tos'), '/re/tos/bar1'),
    ('/re/{surname:re(to.)}/bar2', 'GET', dict(surname='tok'), '/re/tok/bar2/'),

    ('/path/{pth:path()}/end', 'GET', dict(pth='this/path/to'), '/path/this/path/to/end'),
    ('/path1/{pth:path()}end', 'GET', dict(pth='this/path/to-'), '/path1/this/path/to-end'),
]


def expand_params():
    ret = []
    for it in route_meth_handler_path:
        rule, meth, handler, path = it
        name = None
        if '@' in rule:
            name, rule = rule.split('@', 1)
        if not isinstance(path, list):
            path = [path]
        for p in path:
            ret.append([name, rule, meth, handler, p])
    return ret


def make_router():
    router = RadiRouter()
    for it in route_meth_handler_path:
        rule, meth, handler, path = it
        name = None
        if '@' in rule:
            name, rule = rule.split('@', 1)
        router.add(rule, meth, handler, name=name or None)
    return router


def exist_rule_paths():
    seen = set()
    ret = []
    for it in expand_params():
        name, rule, meth, handler, path = it
        print(name or '<no>', rule)
        pattern = RadiRouter.to_pattern(rule)
        if handler not in [404, 405] and pattern not in seen:
            ret.append([name, rule, path])
            seen.add(pattern)
    return ret


@pytest.fixture
def fresh_router():
    return make_router()


@pytest.fixture(scope='class')
def router():
    return make_router()


@pytest.fixture
def routes():
    return route_meth_handler_path[:]


@pytest.fixture(params = expand_params())
def routes_iter(request):
    return request.param


class TestRoutes:
    def test_routes(self, router, routes_iter):
        name, rule, meth, handler, path = routes_iter
        path, _, path_meth = path.partition(':')
        end_point, err404_405 = router.resolve(path, path_meth or meth)
        if end_point is None:
            assert handler in {404, 405}
            assert err404_405[0] == handler
        else:
            assert handler is not None
            route_meth, params, hooks = end_point
            assert route_meth.handler == handler
            if isinstance(meth, str):
                assert route_meth.name == meth
            else:
                assert route_meth.name == meth[0]
            if params:
                assert params == handler
            if name:
                assert router[name][meth] is route_meth


def test_overwrite_error():
    router = RadiRouter()
    route = '/foo/bar'

    def h():
        pass

    router.add(route, ['GET', 'POST'], h)
    with pytest.raises(RouteMethodError) as exc_info:
        router.add(route, 'GET', h)
    assert route in str(exc_info.value)
    assert 'already registered' in str(exc_info.value)


def test_str_repr():
    router = RadiRouter()
    route = '/foo/bar'

    def h():
        pass

    router.add(route, ['GET', 'POST'], h)
    end_point, err404_405 = router.resolve(route, 'GET')
    route_meth, *_ = end_point
    assert h.__qualname__ in str(route_meth)
    assert 'GET' in str(route_meth)
    assert h.__qualname__ in repr(route_meth)
    assert route in repr(route_meth)


class TestRemove:
    @pytest.mark.parametrize(
        'name, rule, path',
        exist_rule_paths()
    )
    def test_remove_route(self, router: RadiRouter, name, rule, path):
        route = router[{rule}]
        assert route
        assert router.resolve(path) is route
        if name:
            assert router[name] is route
        router.remove(rule)
        assert router.resolve(path) is None
        assert router[{rule}] is None
        if name:
            assert router[name] is None
        route_meth, err = router.resolve(path, 'GET')
        assert err[0] == 404


def test_remove_method(fresh_router: RadiRouter):
    router = fresh_router
    route: Route = router.resolve('/foo/bar')
    assert route['GET']
    route.remove_method('GET')
    assert 'GET' not in route.methods
    route_meth, err = router.resolve('/foo/bar', 'GET')
    assert err[0] == 405
    assert router.resolve('/foo/bar')
