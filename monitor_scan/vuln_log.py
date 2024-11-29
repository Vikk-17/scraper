"""
Logging Levels
--------------
DEBUG: 10, used to give detailed info.
INFO: 20, used to confirm that things are working as expected
WARNING: 30, indication of something unexpected happened
ERROR: 40, software has not been able to perform some function
CRITICAL: 50, program itself may be unable to continue running


Logger.level(msg)
"""
import logging 

"""
# Create and configure logger 
logging.basicConfig(
    filename = "newfile.log",
    format = "%(asctime)s %(message)s",
    filemode='w'
)

# Creating an object
logger = logging.getLogger()

# sets the threshold of logger to INFO.
# This means that all the message below that level
# will be ignored
logger.setLevel(logging.INFO)
logger.debug("Harmless debug Message")
logger.info("Just an information")
logger.warning("Its a Warning")
logger.error("Did you try to divide by zero")
logger.critical("Internet is down")
"""
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("Product Vulnerability Scanner")

