main.py
from fastapi import FastAPI

# Create an instance of the FastAPI class
app = FastAPI()

# Define a path operation (or "route") for the root URL ("/")
@app.get("/")
def read_root():
    """
    This is the first endpoint. It handles GET requests to the root path.
    It returns a simple JSON object.
    """
    return {"Hello": "World"}

# Define another path operation for a specific path
@app.get("/items/{item_id}")
def read_item(item_id: int, q: str | None = None):
    """
    This endpoint demonstrates path parameters (item_id) and query parameters (q).
    :param item_id: The ID of the item (automatically validated as an integer).
    :param q: An optional query string.
    :return: A dictionary containing the item details.
    """
    return {"item_id": item_id, "q": q}

# Education: What is happening in this code?
# 1. from fastapi import FastAPI: We import the main class from the FastAPI library.
# 2. app = FastAPI(): We create a FastAPI application instance. This 'app' object is what Uvicorn will look for.
# 3. @app.get("/") and @app.get("/items/{item_id}"): These are 'decorators' that tell FastAPI the function right below it handles HTTP GET requests for the specified URL path.
# 4. Path and Query Parameters: FastAPI uses standard Python type hints (`item_id: int`, `q: str | None = None`) to automatically handle request data validation and serialization.
