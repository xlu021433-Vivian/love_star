import hashlib
import hmac
import io
from pathlib import Path
import tempfile
import unittest

from PIL import Image
from werkzeug.security import generate_password_hash
from lovestar import create_app


class OwnerPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.app=create_app(self.temp.name,testing=True)
        with self.app.app_context():self.app.extensions['love_initialize_admin']('L5','Owner12345')
        self.owner=self.app.test_client();self.visitor=self.app.test_client()
        self.post(self.owner,'/login',{'username':'L5','password':'Owner12345'})

    def post(self,client,path,data=None):
        client.get('/login',follow_redirects=True)
        with client.session_transaction() as session:token=session.get('csrf')
        return client.post(path,data={'_csrf':token,**(data or {})})

    def test_todo_filters_survive_actions_and_include_archived_projects(self):
        from urllib.parse import urlsplit, parse_qs
        self.post(self.owner,'/todos',{'title':'旅行计划','project':'只在归档里'})
        self.post(self.owner,'/todos',{'title':'另一个项目','project':'日常'})
        result=self.post(self.owner,'/todos/1/archive',{'filter':'open','project':'只在归档里'})
        self.assertEqual(parse_qs(urlsplit(result.location).query),{'filter':['open'],'project':['只在归档里']})
        page=self.owner.get('/todos?filter=archive&project=只在归档里').get_data(as_text=True)
        self.assertIn('旅行计划',page)
        self.assertIn('<option selected>只在归档里</option>',page)
        self.assertNotIn('另一个项目</h2>',page)
        self.assertIn('已归档 <span class="todo-tab-count">1</span>',page)
        self.assertIn('进行中 <span class="todo-tab-count">0</span>',page)
        result=self.post(self.owner,'/todos/1/restore',{'filter':'archive','project':'只在归档里'})
        self.assertEqual(parse_qs(urlsplit(result.location).query)['filter'],['archive'])
        page=self.owner.get('/todos?filter=archive&project=只在归档里').get_data(as_text=True)
        self.assertNotIn('旅行计划</h2>',page)
        self.assertIn('当前项目下没有匹配的待办',page)
        result=self.post(self.owner,'/todos/1/toggle',{'filter':'https://example.com','project':'只在归档里'})
        self.assertEqual(urlsplit(result.location).netloc,'')
        self.assertEqual(parse_qs(urlsplit(result.location).query)['filter'],['open'])
        self.assertIn('进行中',self.owner.get('/todos?filter=unknown').get_data(as_text=True))
        self.assertEqual(self.visitor.get('/todos?filter=archive').status_code,302)

    def test_legacy_public_records_photos_profile_and_anniversaries_are_closed(self):
        with self.app.app_context():
            db=self.app.extensions['love_db']()
            db.execute("INSERT INTO moments(author_id,title,content,day,mood,public,photo,created_at,updated_at) VALUES(1,'legacy-secret','secret-text','2025-01-01','daily',1,?,'now','now')",('a'*32+'.jpg',))
            db.execute("INSERT INTO anniversaries(author_id,title,day,public) VALUES(1,'secret-date','2025-01-01',1)")
            db.execute("INSERT INTO settings VALUES('public_profile','1')")
            db.execute("INSERT INTO settings VALUES('name_one','secret-name')");db.commit()
        (Path(self.temp.name)/'uploads'/('a'*32+'.jpg')).write_bytes(b'private')
        for path in ('/','/?view=public','/?q=legacy','/moments/1','/anniversaries','/settings','/todos','/wishes'):
            response=self.visitor.get(path)
            self.assertEqual(response.status_code,302,path)
            for secret in ('legacy-secret','secret-text','secret-date','secret-name'):self.assertNotIn(secret,response.get_data(as_text=True))
            self.assertIn('no-store',response.headers['Cache-Control'])
        self.assertEqual(self.visitor.get('/media/'+('a'*32)+'.jpg').status_code,404)
        self.assertNotIn('secret-name',self.visitor.get('/login').get_data(as_text=True))
        self.assertIn('legacy-secret',self.owner.get('/').get_data(as_text=True))

    def test_legacy_partner_sessions_and_invitations_cannot_enter(self):
        password=generate_password_hash('Partner123')
        with self.app.app_context():
            db=self.app.extensions['love_db']();db.execute("INSERT INTO accounts(id,username,password_hash,role) VALUES(2,'Partner',?,'partner')",(password,));db.commit()
        partner=self.app.test_client()
        with partner.session_transaction() as session:
            session['love_uid']=2;session['love_stamp']=hmac.new(self.app.secret_key.encode(),(password+':0').encode(),hashlib.sha256).hexdigest()
        self.assertEqual(partner.get('/').status_code,302)
        self.assertEqual(self.post(partner,'/login',{'username':'Partner','password':'Partner123'}).status_code,200)
        self.assertEqual(partner.get('/todos').status_code,302)
        for client in (self.visitor,self.owner):
            self.assertEqual(client.get('/join').status_code,404)
            self.assertEqual(self.post(client,'/invite').status_code,404)

    def test_new_writes_ignore_public_fields_and_owner_only_todos(self):
        response=self.post(self.owner,'/write',{'title':'mine','content':'private','day':'2025-01-01','mood':'daily','public':'1','confirm_public':'1'})
        self.assertEqual(response.status_code,302,response.data)
        self.post(self.owner,'/anniversaries',{'title':'day','day':'2025-01-01','public':'1','confirm_public':'1'})
        self.post(self.owner,'/settings',{'name_one':'me','name_two':'you','public_profile':'1'})
        self.assertEqual(self.post(self.owner,'/todos',{'title':'task','project':'daily','priority':'1','assignee':'1'}).status_code,302)
        self.post(self.owner,'/todos/1/toggle');self.post(self.owner,'/todos/1/archive')
        self.assertIn('task',self.owner.get('/todos?filter=archive').get_data(as_text=True))
        self.post(self.owner,'/todos/1/restore')
        with self.app.app_context():
            db=self.app.extensions['love_db']()
            self.assertEqual(db.execute('SELECT public FROM moments').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT public FROM anniversaries').fetchone()[0],0)
            self.assertEqual(db.execute("SELECT value FROM settings WHERE key='public_profile'").fetchone()[0],'0')
        self.assertNotIn('公开给访客',self.owner.get('/write').get_data(as_text=True))

    def test_photo_trash_restore_csrf_escaping_and_pages(self):
        raw=io.BytesIO();picture=Image.new('RGB',(30,30),'pink');exif=picture.getexif();exif[270]='private-location';picture.save(raw,format='JPEG',exif=exif);raw.seek(0)
        self.post(self.owner,'/write',{'title':'<script>bad</script>','content':'<img src=x onerror=bad>','day':'2025-01-01','mood':'daily','photo':(raw,'private.jpg')})
        with self.app.app_context():photo=self.app.extensions['love_db']().execute('SELECT photo FROM moments').fetchone()[0]
        with Image.open(Path(self.temp.name)/'uploads'/photo) as image:self.assertEqual(dict(image.getexif()),{})
        page=self.owner.get('/moments/1').get_data(as_text=True);self.assertIn('&lt;script&gt;',page);self.assertNotIn('<script>bad',page)
        self.post(self.owner,'/moments/1/trash');self.assertEqual(self.owner.get('/media/'+photo).status_code,404)
        self.post(self.owner,'/moments/1/restore')
        response=self.owner.get('/media/'+photo);self.assertEqual(response.status_code,200);response.close()
        self.assertEqual(self.owner.post('/write',data={}).status_code,400)
        for path in ('/','/anniversaries','/wishes','/todos','/settings','/trash','/write','/moments/1/edit'):
            self.assertEqual(self.owner.get(path).status_code,200,path)
