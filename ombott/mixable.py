

class MixableMeta(type):
    __mixins_special__ = {'on_new', 'on_init'}

    def __new__(cls, name, bases, dct):
        mixins = []
        if (mixins_set := dct.get('_as_mixins')):
            bases_ = []
            for m in bases:
                if m in mixins_set:
                    mixins.append(m)
                else:
                    bases_.append(m)
            bases = tuple(bases_)
        if mixins:
            cls._mixin(dct, *mixins)
        out_cls = super().__new__(cls, name, bases, dct)
        return out_cls

    def __init__(cls, name, bases, dct):
        if name == 'Mixable':
            return

        cls_init = cls.__init__
        cls_new = cls.__new__

        def new_wrapper(cls, *a, **kw):
            self = cls_new(cls, *a, **kw)
            on_new_mixins = cls.__mixins_special__['on_new']
            [new(self, *a, **kw) for new in on_new_mixins]
            return self

        def init_wrapper(self, *a, **kw):
            cls_init(self, *a, **kw)
            on_init_mixins = self.__mixins_special__['on_init']
            [init(self, *a, **kw) for init in on_init_mixins]

        cls.__new__ = new_wrapper
        cls.__init__ = init_wrapper

    @classmethod
    def _mixin(cls, dct, *mixins):
        special = {k: [] for k in cls.__mixins_special__}
        slots = [*dct.get('__slots__', [])]
        for mixin_cls in mixins:
            mixin_slots = set(getattr(mixin_cls, '__slots__', []))
            for k, v in mixin_cls.__dict__.items():
                if k in mixin_slots:
                    continue
                if k == '__slots__':
                    slots.extend(v)
                elif k in special:
                    special[k].append(v)
                elif not k.startswith('__') and k not in dct:
                    dct[k] = v
        dct['__mixins_special__'] = special
        if slots:
            dct['__slots__'] = tuple(set(slots))


class Mixable(metaclass=MixableMeta):
    pass


if __name__ == '__main__':

    class BaseQQ:
        def __new__(cls, *a, **kw):
            self = super().__new__(cls)
            self.base = 'base'
            return self

    class qmixin:
        __slots__ = ('_a',)

        def on_init(self, *a, **kw):
            self._a = 'a'

        @classmethod
        def get_name(cls):
            return cls.__name__

        @property
        def a(self):
            return self._a

    class QQ(Mixable, BaseQQ, qmixin):
        __slots__ = ('b',)
        _as_mixins = {qmixin}

        def __init__(self):
            super().__init__()

        def __getattr__(self, k):
            pass

    assert QQ.get_name() == QQ.__name__

    qq = QQ()

    assert qq.a == 'a'
    assert qq.base == 'base'
