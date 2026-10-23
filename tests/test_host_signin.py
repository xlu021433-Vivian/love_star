"""Host cookies are verified on every private request; standalone auth remains separate."""
import io
import re
import tempfile
import unittest
from flask import Flask, session
from lovestar import create_app
from lovestar.integration import mount


class HostSignInTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='love-host-')
        self.addCleanup(self.temp.cleanup)
        self.host=Flask(__name__);self.host.secret_key='isolated-test-host-only';self.host.testing=True
        self.version='current'
        def resolve():
            if session.get('owner')==1 and session.get('version')==self.version:
                return {'id':1,'username':'L5'}
        self.resolve=resolve
        self.love=mount(self.host,self.temp.name,owner_resolver=resolve)
        self.owner=self.host.test_client();self.guest=self.host.test_client()
        with self.owner.session_transaction() as state:state.update(owner=1,version='current')

    def post(self,path,data=None):
        page=self.owner.get('/love/').get_data(as_text=True)
        token=re.search(r'name="_csrf" value="([^"]+)"',page)[1]
        return self.owner.post(path,data={'_csrf':token,**(data or {})})

    def test_first_owner_visit_initializes_once_and_guest_cannot_claim_it(self):
        self.assertIn('使用站主账号进入',self.guest.get('/love/login').get_data(as_text=True))
        with self.love.app_context():self.assertEqual(self.love.extensions['love_db']().execute('SELECT COUNT(*) FROM accounts').fetchone()[0],0)
        self.assertEqual(self.owner.get('/love/').status_code,200)
        self.assertEqual(self.owner.get('/love/settings').status_code,200)
        with self.love.app_context():
            conn=self.love.extensions['love_db']()
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM accounts').fetchone()[0],1)
            self.assertEqual(conn.execute("SELECT value FROM settings WHERE key='host_owner_id'").fetchone()[0],'1')
        for path in ['/love/','/love/settings','/love/todos','/love/wishes','/love/anniversaries']:
            self.assertEqual(self.guest.get(path,headers={'X-Role':'admin','X-User':'L5'}).status_code,302)
        self.assertEqual(self.guest.post('/love/write',data={'title':'fake'}).status_code,404)
        self.assertEqual(self.guest.get('/love/register').status_code,404)

    def test_parent_logout_and_credential_change_revoke_existing_private_cookie(self):
        self.post('/love/write',{'title':'private-note','content':'private-text','day':'2025-01-01','mood':'daily'})
        self.assertIn('private-note',self.owner.get('/love/').get_data(as_text=True))
        self.version='revoked'
        self.assertEqual(self.owner.get('/love/').status_code,302)
        self.assertNotIn('private-note',self.owner.get('/love/login').get_data(as_text=True))
        self.version='current'
        with self.owner.session_transaction() as state:state.clear();state['member_id']=1
        self.assertEqual(self.owner.get('/love/').status_code,302)
        self.assertEqual(self.owner.post('/love/todos',data={'title':'fake'}).status_code,404)

    def test_existing_journal_is_preserved_and_cannot_be_rebound_to_another_owner(self):
        separate=create_app(self.temp.name,testing=True)
        with separate.app_context():
            separate.extensions['love_initialize_admin']('Before','OldPass123')
            conn=separate.extensions['love_db']();conn.execute("INSERT INTO wishes(author_id,title,updated_at) VALUES(1,'kept-wish','now')");conn.commit()
            previous=conn.execute('SELECT password_hash FROM accounts').fetchone()[0]
        self.assertIn('kept-wish',self.owner.get('/love/wishes').get_data(as_text=True))
        with self.love.app_context():self.assertEqual(self.love.extensions['love_db']().execute('SELECT password_hash FROM accounts').fetchone()[0],previous)
        mount(self.host,self.temp.name,owner_resolver=lambda:{'id':2,'username':'Other'})
        self.assertEqual(self.owner.get('/love/').status_code,403)

    def test_private_writes_todo_actions_and_failed_photo_keep_text(self):
        response=self.post('/love/write',{'title':'a memory','content':'keep <these> words','day':'2025-01-01','mood':'travel','photo':(io.BytesIO(b'not an image'),'broken.jpg')})
        self.assertEqual(response.status_code,400)
        page=response.get_data(as_text=True)
        self.assertIn('keep &lt;these&gt; words',page);self.assertIn('文字已保留',page);self.assertIn('value="travel" selected',page)
        self.assertEqual(self.post('/love/todos',{'title':'picnic','return_home':'1'}).location,'/love/')
        self.assertEqual(self.post('/love/todos/1/toggle').status_code,302)
        self.assertIn('picnic',self.owner.get('/love/todos?filter=done').get_data(as_text=True))
        invalid=self.post('/love/todos',{'title':'keep-task','notes':'keep-note','project':'trip','priority':'bad'})
        self.assertEqual(invalid.status_code,400)
        self.assertIn('keep-task',invalid.get_data(as_text=True));self.assertIn('keep-note',invalid.get_data(as_text=True))
        with self.love.app_context():self.assertEqual(self.love.extensions['love_db']().execute('SELECT COUNT(*) FROM moments').fetchone()[0],0)

    def test_milestone_today_is_shown_on_the_actual_hundredth_day(self):
        from lovestar import today
        import datetime as dt
        first=(today()-dt.timedelta(days=99)).isoformat()
        self.post('/love/settings',{'name_one':'me','start_day':first})
        self.assertIn('就是今天',self.owner.get('/love/').get_data(as_text=True))
