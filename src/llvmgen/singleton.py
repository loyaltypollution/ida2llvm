class SingletonParent(object):
    _cls_children = { }


class Singleton(type):
    _instances = { }
    def __call__(cls, *args, **kwargs):
        if not issubclass(cls, SingletonParent):
            raise TypeError(f"{cls} must be SingletonParent type!")
        if Singleton not in cls._instances:
            cls._instances[Singleton] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[Singleton]


class MethodGlobal(type):
    def __call__(cls, name, *args, **kwargs):
        _instances = Singleton._instances[Singleton]._cls_children
        if (cls, name) not in _instances:
            _instances[(cls, name)] = super(MethodGlobal, cls).__call__(name, *args, **kwargs)
        return _instances[(cls, name)]