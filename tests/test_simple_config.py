from ombott.common_helpers import NameSpace
import pytest
from ombott import SimpleConfig


@SimpleConfig.keys_holder
class BaseConfig(SimpleConfig):
    a = None
    b = 2
    c = None


class Config(BaseConfig):
    a = 'a'


cfg = BaseConfig(dict(a='a', ignored=1))

cfg_from_none = BaseConfig()
cfg_from_none.a = 'a'


@pytest.fixture(params = [(Config, type), (cfg, NameSpace), (cfg_from_none, NameSpace)])
def config_class(request):
    return request.param


def test_simple_config(config_class):
    config, cls = config_class

    assert isinstance(config, cls)
    assert config.a == 'a'
    assert config.b == 2
    assert config.c is None
    assert set(config.keys()) == set(['a', 'b', 'c'])
    assert config.get('a') == 'a'
    assert config.get('b') == 2
    assert config.get('nokey') is None
    assert config.get('nokey', True) is True
    assert set(config.items()) == set([('a', 'a'), ('b', 2), ('c', None)])


def test_simple_config_key_holder_error():
    with pytest.raises(RuntimeError) as exc_info:
        @SimpleConfig.keys_holder
        class Config(BaseConfig):
            a = 'a'
    assert 'BaseConfig' in str(exc_info.value)


def test_simple_config_key_error():
    with pytest.raises(KeyError) as exc_info:
        class Config(BaseConfig):
            unexp_key = 'd'
    assert 'unexp_key' in str(exc_info.value)

