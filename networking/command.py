class Command:
    def __init__(self, type_, description, args, method):
        self.type = type_
        self.description = description
        self.args = args
        self.method = method

    def __call__(self, *args, **kwargs):
        return self.method(*args, **kwargs)