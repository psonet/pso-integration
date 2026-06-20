"""Force a platform-specific wheel.

The wheel bundles a per-platform native shared library, so it is NOT
pure-python and must carry a platform tag (otherwise pip would install the
wrong arch's lib). Overriding `has_ext_modules` makes the `wheel` builder tag
the artifact platform-specific; CI additionally passes the exact target tag
via `--plat-name` (the lib is cross-built, so the build host's tag is wrong).
"""

from setuptools import setup
from setuptools.dist import Distribution


class _BinaryDistribution(Distribution):
    def has_ext_modules(self) -> bool:  # noqa: D401
        return True

    # Cross-built libs: never assume the build host's interpreter/arch is the
    # target. `--plat-name` (passed by CI) overrides the tag regardless.
    def is_pure(self) -> bool:
        return False


setup(distclass=_BinaryDistribution)
