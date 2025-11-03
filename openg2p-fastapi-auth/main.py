"""Main entry point for the openg2p-fastapi-auth application"""

import os

from openg2p_fastapi_auth.app import Initializer

# Set environment variables to disable database connection for testing
os.environ["common_db_datasource"] = ""
os.environ["common_db_driver"] = ""
os.environ["common_db_username"] = ""
os.environ["common_db_password"] = ""
os.environ["common_db_hostname"] = ""
os.environ["common_db_port"] = "0"
os.environ["common_db_dbname"] = ""

# Create the initializer and get the app
initializer = Initializer()
app = initializer.return_app()

if __name__ == "__main__":
    # This allows running with: python main.py
    initializer.main()
