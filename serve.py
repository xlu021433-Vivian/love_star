import os
from waitress import serve
from lovestar import create_app

if __name__ == "__main__":
    serve(create_app(),host=os.environ.get("LOVE_HOST","127.0.0.1"),port=int(os.environ.get("PORT","8002")),threads=4)
