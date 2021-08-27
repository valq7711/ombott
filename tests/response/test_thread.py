
import pytest
from ombott.response import Response
import threading
from copy import deepcopy

result = {'seq':[]}

def run_thread(func, *a):
    t = threading.Thread(target=func, args=a)
    return t

@pytest.fixture
def args3():
    bodies = ['b1', 'b2', 'b3']
    statuses = [200, 400, 500]
    headers_set = [
        dict(h1='h1', h11='h11',),
        dict(h2 = 'h2'),
        dict(h3 = 'h3'),
    ]
    cookies_set = [
        dict(c11='c11', c12='c12'),
        dict(c2 = 'c2'),
        dict(c31 = 'c31', c32 = 'c32'),
    ]
    ret = []
    for body, status, headers, cookies in zip(bodies, statuses, headers_set, cookies_set):
        ret.append(dict(body=body, status=status, headers=headers, cookies=cookies))
    return ret


@pytest.fixture(scope='module')
def ombott_response():
    return Response()

@pytest.fixture
def init_resp(ombott_response):
    def init(kwargs, key, evnt_done=None, evnt_play=None):
        cookies = kwargs.pop('cookies')
        ombott_response.__init__(**kwargs)
        [ombott_response.set_cookie(k,v) for k,v in cookies.items()]
        resp = ombott_response
        result['seq'].append(key)
        evnt_done and evnt_done.set()
        evnt_play and evnt_play.wait()
        result['seq'].append(key)
        result[key] = dict(
            body = resp.body,
            status = resp._status_code,
            headers = dict(resp.headers),
            cookies = {k:v.value for k,v in resp._cookies.items()}
        )
        return ombott_response
    return init


def test_thread(init_resp, args3, ombott_response):
    a1, a2, a3 = args3
    assert  init_resp(deepcopy(a1), 't1') is ombott_response
    evnt_done = threading.Event()
    evnt_play = threading.Event()
    t2 = run_thread(init_resp, deepcopy(a2), 't2', evnt_done, evnt_play)
    t3 = run_thread(init_resp, deepcopy(a3), 't3', None, None)
    t2.start()
    evnt_done.wait()
    t3.start()
    t3.join()
    evnt_play.set()
    t2.join()
    assert ombott_response._status_code == a1['status']
    assert ombott_response.body == a1['body']

    assert result['t1'] == a1
    assert result['t2'] == a2
    assert result['t3'] == a3
    assert ','.join(result['seq']) == 't1,t1,t2,t3,t3,t2'
