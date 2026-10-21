"""Mount without sharing the host app's database, secret, cookies or identities."""
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from . import create_app


def mount(app,data_dir,secure=False,prefix="/love"):
    original=app.extensions.setdefault("love_original_wsgi",app.wsgi_app)
    love=create_app(data_dir,cookie_path=prefix,secure=secure)
    app.extensions["love_star"]=love
    app.wsgi_app=DispatcherMiddleware(original,{prefix:love})
    return love
