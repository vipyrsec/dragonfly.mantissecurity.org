import functools
import logging

logger = logging.getLogger(__file__)


def debug_func(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        args_repr = [repr(a) for a in args]
        kwargs_repr = [f"{key}={repr(val)}" for key, val in kwargs.items()]
        logger.debug(f"calling {func.__name__} with {args_repr=}, {kwargs_repr=}")
        retval = func(*args, **kwargs)
        logger.debug(f"exiting {func.__name__} with return: {retval}")

    return wrapper
