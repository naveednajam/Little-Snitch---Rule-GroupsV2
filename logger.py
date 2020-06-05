import logging
import logging.handlers
import os


class OneLineExceptionFormatter(logging.Formatter):

    def formatException(self, exc_info):
        result = super().formatException(exc_info)
        return repr(result)

    def format(self, record):
        result = super().format(record)
        if record.exc_text:
            result = result.replace("\n", "")
        return result


def setup(name):
    log = logging.getLogger(name)
    # create Handler
    c_handler = logging.StreamHandler()
    # f_handler = logging.FileHandler('hosts.log')
    f_handler = logging.handlers.WatchedFileHandler(os.environ.get("LOGFILE", "rulegroups.log"))

    # create formatter to convert multi-line logs to single line logs
    f_formatter = logging.Formatter('%(asctime)s | %(name)s | %(module)s | %(funcName)s | %(levelname)s | %(message)s',
                                    '%d/%m/%Y %H:%M:%S')
    c_formatter = OneLineExceptionFormatter(
        '%(asctime)s | %(name)s | %(module)s | %(funcName)s | %(levelname)s | %(message)s', '%d/%m/%Y %H:%M:%S')

    # add formatter to handler
    c_handler.setFormatter(c_formatter)
    f_handler.setFormatter(f_formatter)

    # default log leve
    log.setLevel(os.environ.get("LOGLEVEL", "INFO"))

    # add handler to log object
    log.addHandler(c_handler)
    log.addHandler(f_handler)
