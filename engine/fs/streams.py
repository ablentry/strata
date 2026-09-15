class NoSuchStream(KeyError):

    def __init__(self, name, stream, available):
        self.name = name
        self.stream = stream
        self.available = list(available)
        super().__init__(
            "%s has no stream named %r. It carries: %s"
            % (name or "This record", stream,
               ", ".join(repr(a) for a in self.available)
               or "no named streams"))

class UnsupportedStream(ValueError):

    def __init__(self, fsname, stream):
        self.fs = fsname
        self.stream = stream
        super().__init__(
            "%s in this build cannot read the named stream %r. Its name and "
            "size are listed from the record; its contents are not decoded."
            % (fsname, stream))
