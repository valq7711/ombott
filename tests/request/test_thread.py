
import pytest
from ombott.request import Request
import threading
import time

result = {'seq':[]}

def run_thread(func, *a):
    t = threading.Thread(target=func, args=a)
    return t


@pytest.fixture
def env3():
    e1 = {'PATH_INFO': '/t1'}
    e2 = {'PATH_INFO': '/t2'}
    e3 = {'PATH_INFO': '/t3'}
    return e1, e2, e3


@pytest.fixture
def ombott_request():
    return Request()

@pytest.fixture
def init_request(ombott_request):
    def init(env, key, evnt_done=None, evnt_play=None):
        ombott_request.__init__(env)
        result['seq'].append(key)
        evnt_done and evnt_done.set()
        evnt_play and evnt_play.wait()
        assert ombott_request.environ is env
        assert ombott_request.path == env['PATH_INFO']
        assert ombott_request.path == ombott_request._env_get('PATH_INFO')
        result[key] = ombott_request.path
        return ombott_request
    return init

def test_thread(init_request, env3, ombott_request):
    e1, e2, e3 = env3
    assert  init_request(e1, 't1') is ombott_request
    evnt_done = threading.Event()
    evnt_play = threading.Event()
    t2 = run_thread(init_request, e2, 't2', evnt_done, evnt_play)
    t3 = run_thread(init_request, e3, 't3', None, None)
    t2.start()
    evnt_done.wait()
    t3.start()
    t3.join()
    evnt_play.set()
    t2.join()
    assert ombott_request.path == e1['PATH_INFO']
    assert result['t2'] == e2['PATH_INFO']
    assert result['t3'] == e3['PATH_INFO']
    assert ','.join(result['seq']) == 't1,t2,t3'
