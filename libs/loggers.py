import logging
import os


class Loggers:
    def __init__(self, logger_name, log_file_path, log_level='INFO'):
        if os.path.exists(log_file_path):
            os.remove(log_file_path)

        self.file_logger = self.enable_file_logger(logger_name, log_level, log_file_path)
        self.console_logger = self.enable_console_logger(logger_name, log_level)

    @staticmethod
    def enable_console_logger(logger_name, log_level):
        logger_name = f'console-{logger_name}'
        console_log = logging.getLogger(logger_name)
        console_log.setLevel(log_level)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                           datefmt='%d-%b-%y %H:%M:%S')
        console_handler.setFormatter(console_format)
        console_log.addHandler(console_handler)

        return console_log

    @staticmethod
    def enable_file_logger(logger_name, log_level, log_file_path):
        logger_name = f'file-{logger_name}'

        if not os.path.exists(log_file_path):
            open(log_file_path, 'w').close()

        file_log = logging.getLogger(logger_name)
        file_log.setLevel(log_level)

        file_handler = logging.FileHandler(log_file_path)
        file_handler.setLevel(logging.DEBUG)
        # file_format = logging.Formatter('["%(asctime)s","%(levelname)s","%(message)s"]',
        #                                 datefmt='%d-%b-%y %H:%M:%S')
        file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                        datefmt='%d-%b-%y %H:%M:%S')
        file_handler.setFormatter(file_format)
        file_log.addHandler(file_handler)

        return file_log

    def entry(self, level, msg, to_base64=False, hide_base64=True, replace_chars=True):
        for handler in [self.console_logger, self.file_logger]:
            log_level = getattr(handler, level)

            if handler == self.file_logger:
                if to_base64:
                    if hide_base64:
                        msg = f'Base64 log message hidden due to its length'

                    else:
                        encoded_msg = b64encode(bytes(msg, 'utf-8'))
                        msg = f'Base64 encoded log: {encoded_msg}'

                else:
                    if replace_chars and isinstance(msg, str):
                        msg = msg.replace('"', "'").replace('\n', ' ')

            log_level(msg)
