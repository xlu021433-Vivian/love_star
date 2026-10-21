"""Owner-only regression tests; partner/public sharing is intentionally retired."""
import datetime as dt
import tempfile
import unittest
from werkzeug.security import generate_password_hash
from lovestar import LoveError,countdown,create_app


class InitializationTests(unittest.TestCase):
    def test_owner_credentials_single_admin_and_persistent_namespace(self):
        with tempfile.TemporaryDirectory() as root:
            app=create_app(root,testing=True)
            with app.app_context():
                initialize=app.extensions['love_initialize_admin']
                for name,password in [('TooLongNameHere','Owner123'),('L5','short')]:
                    with self.assertRaises(LoveError):initialize(name,password)
                initialize('L5','Owner12345')
                with self.assertRaises(LoveError):initialize('Other','Owner12345')
                row=app.extensions['love_db']().execute('SELECT * FROM accounts').fetchone()
                self.assertNotEqual(row['password_hash'],'Owner12345')
            restarted=create_app(root,testing=True)
            self.assertEqual(app.secret_key,restarted.secret_key)
            self.assertEqual(restarted.config['SESSION_COOKIE_NAME'],'love_star_session')
            client=restarted.test_client();client.get('/login')
            with client.session_transaction() as session:token=session['csrf']
            self.assertEqual(client.post('/login',data={'_csrf':token,'username':'l5','password':'Owner12345'}).status_code,200)
            self.assertEqual(client.post('/login',data={'_csrf':token,'username':'L5','password':'Owner12345'}).status_code,302)

    def test_unconfigured_space_has_no_public_registration(self):
        with tempfile.TemporaryDirectory() as root:
            app=create_app(root,testing=True);client=app.test_client()
            self.assertEqual(client.get('/').location,'/login')
            self.assertIn('管理员尚未设置',client.get('/login').get_data(as_text=True))
            for path in ('/join','/register','/invite'):
                self.assertEqual(client.get(path).status_code,404 if path!='/invite' else 404)


class CountdownTests(unittest.TestCase):
    def test_next_occurrence_one_time_past_and_leap_day(self):
        self.assertEqual(countdown("2020-02-29",True,dt.date(2025,2,27))["days"],1)
        self.assertEqual(countdown("2020-02-29",True,dt.date(2025,2,28))["days"],0)
        self.assertEqual(countdown("2020-02-29",True,dt.date(2025,3,1))["target"],"2026-02-28")
        self.assertEqual(countdown("2025-01-01",False,dt.date(2025,1,2))["days"],-1)
        self.assertEqual(countdown("2028-01-01",True,dt.date(2025,1,2))["target"],"2028-01-01")
