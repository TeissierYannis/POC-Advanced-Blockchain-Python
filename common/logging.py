import logging

from common.colors import bcolors

DEFAULT_COLOR = bcolors.ENDC


def setup_logging():
    # Change color of the logging messages asctime to green, levelname to bold and message to default color
    # Allow all levels to be logged
    logging.basicConfig(level=logging.DEBUG,
                        format=f"{bcolors.OKGREEN}[%(asctime)s]{bcolors.ENDC}[%(levelname)s] %(message)s{DEFAULT_COLOR}")
    logger = logging.getLogger(__name__)
    # Change the color of the logging levels- for debug to cyan, for info to green, for warning to yellow and for error to red
    logging.addLevelName(logging.DEBUG, "\033[1;36m%s\033[1;0m" % logging.getLevelName(logging.DEBUG))
    logging.addLevelName(logging.INFO, "\033[1;32m%s\033[1;0m" % logging.getLevelName(logging.INFO))
    logging.addLevelName(logging.WARNING, "\033[1;33m%s\033[1;0m" % logging.getLevelName(logging.WARNING))
    logging.addLevelName(logging.ERROR, "\033[1;31m%s\033[1;0m" % logging.getLevelName(logging.ERROR))
    logging.addLevelName(logging.DEBUG, "\033[1;36m%s\033[1;0m" % logging.getLevelName(logging.DEBUG))

    return logger


logger = setup_logging()
