"""Mount with separate data and optional server-verified owner authentication."""
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from . import create_app


def mount(app,data_dir,secure=False,prefix="/love",owner_resolver=None,login_url="/login?next=/love/"):
    original=app.extensions.setdefault("love_original_wsgi",app.wsgi_app)
    love=create_app(data_dir,cookie_path=prefix,secure=secure)
    if owner_resolver is not None:
        love.config['LOVE_HOST_LOGIN_URL']=login_url

        def owner_gateway(environ,start_response):
            # Only server-verified identity crosses this boundary, never a role header or query parameter.
            forwarded=environ.copy()
            forwarded.pop('lovestar.host_owner',None)
            with app.request_context(environ.copy()):
                identity=owner_resolver()
            if identity is not None:
                forwarded['lovestar.host_owner']=identity
            return love(forwarded,start_response)
        mounted=owner_gateway
    else:
        mounted=love
    app.extensions["love_star"]=love
    app.wsgi_app=DispatcherMiddleware(original,{prefix:mounted})
    return love
