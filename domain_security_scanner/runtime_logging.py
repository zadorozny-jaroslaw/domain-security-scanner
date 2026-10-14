from __future__ import annotations

import logging
import sys


LOGGER_NAME = "domain_security_scanner"
TRACE_LEVEL = 5
_CLI_HANDLER_MARKER = "_domain_security_scanner_cli_handler"

logging.addLevelName(TRACE_LEVEL, "TRACE")


def verbosity_to_level(*, verbose: int = 0, quiet: bool = False) -> int:
    """Map CLI verbosity options to the package logging threshold."""
    if quiet:
        return logging.ERROR
    if verbose >= 2:
        return TRACE_LEVEL
    if verbose == 1:
        return logging.DEBUG
    return logging.INFO


def configure_cli_logging(*, verbose: int = 0, quiet: bool = False) -> logging.Logger:
    """Configure scanner-package logging for one CLI invocation.

    Only the ``domain_security_scanner`` logger hierarchy is configured. This avoids
    enabling verbose output from third-party libraries such as requests/urllib3.

    The CLI-owned handler is replaced on every invocation so repeated ``main()``
    calls in tests do not accumulate duplicate handlers or retain an old stderr.
    """
    package_logger = logging.getLogger(LOGGER_NAME)
    package_logger.setLevel(verbosity_to_level(verbose=verbose, quiet=quiet))
    package_logger.propagate = False

    for handler in list(package_logger.handlers):
        if getattr(handler, _CLI_HANDLER_MARKER, False):
            package_logger.removeHandler(handler)
            handler.close()

    handler = logging.StreamHandler(sys.stderr)
    setattr(handler, _CLI_HANDLER_MARKER, True)
    handler.setLevel(TRACE_LEVEL)
    handler.setFormatter(logging.Formatter("%(message)s"))
    package_logger.addHandler(handler)

    return package_logger
