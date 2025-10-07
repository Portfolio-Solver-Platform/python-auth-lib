import time


class CachedGetter:
    """
    A class that caches the value of a getter for a certain amount of time.
    :param getter: A function that returns the value to be cached. If the function raises a DontCacheException, the cache will not be updated.
    :param time_until_cache: The time in seconds until the cache expires.
    """

    def __init__(self, getter, time_until_cache: int):
        self.getter = getter
        self.value = None
        self.time_until_cache = time_until_cache
        self.last_update = 0  # Last time the value was updated

    def update(self):
        try:
            self.value = self.getter()
            self.last_update = time.time()
        except DontCacheException:
            pass

    def get(self):
        if time.time() - self.last_update > self.time_until_cache:
            self.update()

        return self.value


class DontCacheException(Exception):
    pass
