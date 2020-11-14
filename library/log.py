import logging
from colorlog import ColoredFormatter


def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    color_formatter = ColoredFormatter(
            "%(log_color)s[%(asctime)s] [%(levelname)-4s]%(reset)s - %(message)s",
            datefmt='%d-%m-%y %H:%M:%S',
            reset=True,
            log_colors={
                'DEBUG':    'cyan',
                'INFO':     'green',
                'WARNING':  'bold_yellow',
                'ERROR':    'bold_red',
                'CRITICAL': 'bold_red',
            },
            secondary_log_colors={},
            style='%')
    logging_handler = logging.StreamHandler()
    logging_handler.setFormatter(color_formatter)
    logger.addHandler(logging_handler)
    #record logg
    file_handler = logging.FileHandler('errors.log')
    file_handler.setLevel(logging.ERROR)
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
# setup logging for script
setup_logging()
logger = logging.getLogger(__name__)