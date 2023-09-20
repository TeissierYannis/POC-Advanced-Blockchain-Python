def exception_handler(exc_type, exc_value, exc_traceback):
    # Get the message from the exception
    message = exc_value.args[0]
    # Print the message in red color
    logger.error(f"[EXCEPTION]{bcolors.OKCYAN}{message}{DEFAULT_COLOR}")
    # Call the default exception handler
    sys.__excepthook__(exc_type, exc_value, exc_traceback)