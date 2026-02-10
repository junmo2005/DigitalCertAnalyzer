import logging
from logging.handlers import WatchedFileHandler

def setup_logging(app):
    """配置日志系统"""
    log_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        file_handler = WatchedFileHandler('app.log', encoding='utf-8')
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO)
    except ImportError:
        file_handler = logging.FileHandler('app.log', encoding='utf-8')
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.DEBUG)
    
    app.logger.handlers.clear()
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    
    logging.getLogger('werkzeug').propagate = False
    logging.getLogger('urllib3').propagate = False