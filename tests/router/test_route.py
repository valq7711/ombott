
import pytest
from ombott.router import Route

rule_param_expected_url = [
    ('/static/rule', [[], {}], 'static/rule'),
    ('/s', [[], {}], 's'),
    ('/{:re(to.)}', [('tok',), {}], 'tok'),
    ('/foo/{:re(to.)}', [('tok',), {}], 'foo/tok'),
    ('/foo/{:re(to.)}/bar{some}', [('tok',), dict(some = 'baz')], 'foo/tok/barbaz'),
    ('/foo/{:re(to.)}/bar{some}/{:re(a.)}', [('tok', 'ab'), dict(some = 'baz')], 'foo/tok/barbaz/ab'),
    ('/foo/{:re(to.)}/bar{some}/{:re(a.)}end', [('tok', 'ab'), dict(some = 'baz')], 'foo/tok/barbaz/abend'),
    ('/foo/{:re(to.)}/bar{some}/{other}/end', [('tok',), dict(some = 'baz', other = 'other')], 'foo/tok/barbaz/other/end'),
    ('/foo/{:re(to.)}/bar{some.int()}/{other}/end', [('tok',), dict(some = 5, other = 'other')], 'foo/tok/bar5/other/end'),
    ('/foo/bar{some.int()}/{other}/end', [[], dict(some = 5, other = 'other')], 'foo/bar5/other/end'),
]


@pytest.fixture(params=rule_param_expected_url)
def route_param_expected(request):
    rule, params, expected = request.param
    route = Route(rule)
    return route, params, expected


def test_url(route_param_expected):
    route, [args, kw], expected = route_param_expected
    route: Route = route
    assert route.url(*args, **kw) == expected
