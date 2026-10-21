import datetime as dt
import io
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest

from PIL import Image
from lovestar import LoveError, countdown, create_app


class LoveStarTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="love-test-")
        self.addCleanup(self.temp.cleanup)
        self.app=create_app(self.temp.name,testing=True)
        self.owner=self.app.test_client();self.visitor=self.app.test_client();self.partner=self.app.test_client()
        with self.app.app_context():
            self.app.extensions["love_initialize_admin"]("L5","Owner12345")
        self.login(self.owner,"L5","Owner12345")

    def csrf(self,client):
        client.get("/")
        with client.session_transaction() as session:
            return session["csrf"]

    def post(self,client,path,data=None):
        return client.post(path,data={"_csrf":self.csrf(client),**(data or {})})

    def login(self,client,name,password):
        return self.post(client,"/login",{"username":name,"password":password})

    def invite(self):
        response=self.post(self.owner,"/invite")
        self.assertEqual(response.status_code,200,response.data)
        return re.search(r'value="([\w-]{32})" readonly',response.get_data(as_text=True))[1]

    def join(self,code=None):
        response=self.post(self.partner,"/join",{"username":"Partner","password":"Partner123","confirm":"Partner123","invite":code or self.invite(),"role":"admin"})
        self.assertEqual(response.status_code,302,response.data)
        self.login(self.partner,"Partner","Partner123")

    def memory(self,client=None,public=False,photo=False,title="一起散步",content="不能被陌生人看见的回忆"):
        data=dict(title=title,content=content,day="2025-03-21",mood="daily")
        if public:
            data.update(public="1",confirm_public="1")
        if photo:
            raw=io.BytesIO();image=Image.new("RGB",(32,24),"pink")
            exif=image.getexif();exif[270]="private-camera-location"
            image.save(raw,format="JPEG",exif=exif);raw.seek(0)
            data["photo"]=(raw,"picture.jpg")
        response=self.post(client or self.owner,"/write",data)
        self.assertEqual(response.status_code,302,response.data)
        return int(response.location.rsplit("/",1)[-1])

    def row(self,table,item_id):
        with self.app.app_context():
            return dict(self.app.extensions["love_db"]().execute("SELECT * FROM "+table+" WHERE id=?",(item_id,)).fetchone())

    def test_private_by_default_across_timeline_search_detail_and_photo(self):
        item=self.memory(photo=True)
        photo=self.row("moments",item)["photo"]
        for path in ("/","/?q=散步","/?today=1"):
            text=self.visitor.get(path).get_data(as_text=True)
            self.assertNotIn("不能被陌生人看见",text)
            self.assertNotIn(photo,text)
        self.assertEqual(self.visitor.get(f"/moments/{item}").status_code,404)
        self.assertEqual(self.visitor.get("/media/"+photo).status_code,404)
        self.assertEqual(self.owner.get("/media/"+photo).status_code,200)

    def test_public_requires_confirmation_and_media_visibility_follows_record(self):
        response=self.post(self.owner,"/write",dict(title="公开",content="正文",day="2025-01-01",mood="daily",public="1"))
        self.assertEqual(response.status_code,400)
        item=self.memory(public=True,photo=True)
        photo=self.row("moments",item)["photo"]
        self.assertEqual(self.visitor.get(f"/moments/{item}").status_code,200)
        self.assertEqual(self.visitor.get("/media/"+photo).status_code,200)
        self.post(self.owner,f"/moments/{item}/edit",dict(title="收起",content="私密正文",day="2025-01-01",mood="daily"))
        self.assertEqual(self.visitor.get("/media/"+photo).status_code,404)
        self.assertEqual(self.visitor.get(f"/moments/{item}").status_code,404)

    def test_partner_cannot_escalate_manage_settings_or_edit_owners_memory(self):
        self.join()
        own=self.memory();other=self.memory(self.partner,title="伴侣的记录")
        self.assertEqual(self.partner.get(f"/moments/{own}").status_code,200)
        self.assertEqual(self.partner.get(f"/moments/{own}/edit").status_code,403)
        self.assertEqual(self.post(self.partner,f"/moments/{own}/trash").status_code,403)
        self.assertEqual(self.owner.get(f"/moments/{other}/edit").status_code,200)
        for path in ("/settings","/invite","/partners/1/disable"):
            response=self.post(self.partner,path)
            self.assertEqual(response.status_code,403)
        self.assertEqual(self.row("accounts",2)["role"],"partner")

    def test_invite_single_use_rotation_no_open_registration(self):
        old=self.invite();new=self.invite()
        self.assertNotEqual(old,new)
        invalid=self.post(self.partner,"/join",dict(username="Other",password="Partner123",confirm="Partner123",invite=old))
        self.assertEqual(invalid.status_code,400)
        self.join(new)
        self.assertEqual(self.post(self.owner,"/invite").status_code,400)
        replay=self.post(self.visitor,"/join",dict(username="Other",password="Partner123",confirm="Partner123",invite=new))
        self.assertEqual(replay.status_code,400)
        self.assertEqual(self.visitor.get("/register").status_code,404)

    def test_expired_invite_and_second_admin_are_rejected(self):
        code=self.invite()
        with self.app.app_context():
            connection=self.app.extensions["love_db"]()
            connection.execute("UPDATE invitations SET expires=0");connection.commit()
            with self.assertRaises(LoveError):
                self.app.extensions["love_initialize_admin"]("Admin","Owner12345")
        response=self.post(self.partner,"/join",dict(username="Partner",password="Partner123",confirm="Partner123",invite=code))
        self.assertEqual(response.status_code,400)

    def test_disable_partner_revokes_existing_session_but_preserves_records(self):
        self.join();item=self.memory(self.partner)
        self.post(self.owner,"/partners/2/disable")
        self.assertEqual(self.partner.get(f"/moments/{item}").status_code,404)
        self.assertEqual(self.partner.get("/write").status_code,302)
        self.assertEqual(self.owner.get(f"/moments/{item}").status_code,200)
        self.assertFalse(self.row("accounts",2)["active"])
        self.post(self.owner,"/partners/2/enable")
        self.assertEqual(self.partner.get("/write").status_code,302)
        self.assertEqual(self.login(self.partner,"Partner","Partner123").status_code,302)
        self.assertEqual(self.partner.get("/write").status_code,200)

    def test_profile_dates_and_nicknames_are_private_until_opted_in(self):
        data=dict(name_one="独有昵称甲",name_two="独有昵称乙",start_day="2024-01-01")
        self.post(self.owner,"/settings",data)
        for client,path in ((self.visitor,"/"),(self.owner,"/?view=public")):
            page=client.get(path).get_data(as_text=True)
            self.assertNotIn("独有昵称甲",page)
            self.assertNotIn("2024-01-01",page)
        self.post(self.owner,"/settings",{**data,"public_profile":"1"})
        self.assertIn("独有昵称甲",self.visitor.get("/").get_data(as_text=True))

    def test_private_anniversaries_and_wishes_are_never_rendered_for_visitors(self):
        self.post(self.owner,"/anniversaries",dict(title="私密纪念日",day="2024-05-20",yearly="1"))
        self.post(self.owner,"/wishes",dict(title="秘密共同心愿"))
        for path in ("/","/anniversaries"):
            self.assertNotIn("私密纪念日",self.visitor.get(path).get_data(as_text=True))
        self.assertEqual(self.visitor.get("/wishes").status_code,302)
        self.assertNotIn("秘密共同心愿",self.visitor.get("/").get_data(as_text=True))
        self.assertEqual(self.post(self.visitor,"/anniversaries",dict(title="越权",day="2024-01-01")).status_code,403)

    def test_shared_wishes_and_anniversary_hiding(self):
        self.join()
        self.post(self.owner,"/wishes",dict(title="一起看海"))
        self.post(self.partner,"/wishes/1/toggle")
        self.assertEqual(self.row("wishes",1)["done"],1)
        self.post(self.owner,"/wishes/1/toggle")
        self.assertEqual(self.row("wishes",1)["done"],0)
        self.post(self.owner,"/anniversaries",dict(title="公开纪念日",day="2024-05-20",public="1",confirm_public="1"))
        self.assertIn("公开纪念日",self.visitor.get("/anniversaries").get_data(as_text=True))
        self.post(self.owner,"/anniversaries/1/hide")
        self.assertNotIn("公开纪念日",self.visitor.get("/anniversaries").get_data(as_text=True))
        self.assertEqual(self.partner.get("/anniversaries/1/edit").status_code,403)
        self.assertEqual(self.owner.get("/anniversaries/1/edit").status_code,200)
        self.post(self.owner,"/anniversaries/1/edit",dict(title="修改后的日期",day="2025-01-01",yearly="1"))
        self.assertEqual(self.row("anniversaries",1)["title"],"修改后的日期")

    def test_trash_hides_media_restore_is_private(self):
        item=self.memory(public=True,photo=True)
        photo=self.row("moments",item)["photo"]
        self.post(self.owner,f"/moments/{item}/trash")
        self.assertEqual(self.owner.get("/media/"+photo).status_code,404)
        self.assertEqual(self.visitor.get(f"/moments/{item}").status_code,404)
        self.assertIn("一起散步",self.owner.get("/trash").get_data(as_text=True))
        self.post(self.owner,f"/moments/{item}/restore")
        self.assertEqual(self.owner.get(f"/moments/{item}").status_code,200)
        self.assertFalse(self.row("moments",item)["public"])

    def test_photo_is_reencoded_without_exif_or_original_filename(self):
        item=self.memory(photo=True);name=self.row("moments",item)["photo"]
        self.assertRegex(name,r"^[a-f0-9]{32}\.jpg$")
        with Image.open(Path(self.temp.name)/"uploads"/name) as photo:
            self.assertEqual(photo.format,"JPEG")
            self.assertEqual(dict(photo.getexif()),{})
        self.assertFalse((Path(self.temp.name)/"uploads"/"picture.jpg").exists())

    def test_unsafe_images_xss_and_missing_csrf(self):
        self.assertEqual(self.owner.post("/write",data={}).status_code,400)
        response=self.post(self.owner,"/write",dict(title="image",content="body",day="2024-01-01",mood="daily",photo=(io.BytesIO(b'<svg onload="alert(1)"></svg>'),"a.svg")))
        self.assertEqual(response.status_code,400)
        item=self.memory(public=True,title='<script>alert("x")</script>',content='<img src=x onerror="alert(1)">')
        page=self.visitor.get(f"/moments/{item}").get_data(as_text=True)
        self.assertIn("&lt;script&gt;",page)
        self.assertNotIn('<script>alert("x")</script>',page)

    def test_cookie_namespace_cache_and_persistence(self):
        item=self.memory()
        self.assertEqual(self.app.config["SESSION_COOKIE_NAME"],"love_star_session")
        for path in ("/",f"/moments/{item}","/settings"):
            response=self.owner.get(path)
            self.assertEqual(response.headers["Cache-Control"],"private, no-store")
            self.assertIn("Cookie",response.headers["Vary"])
        restarted=create_app(self.temp.name,testing=True)
        self.assertEqual(restarted.secret_key,self.app.secret_key)
        with restarted.app_context():
            self.assertEqual(restarted.extensions["love_db"]().execute("SELECT COUNT(*) FROM moments").fetchone()[0],1)

    def test_blog_session_field_names_do_not_authenticate_love_star(self):
        with self.visitor.session_transaction() as session:
            session.update(uid=1,member_id=1,auth_stamp="fake",member_stamp="fake")
        self.assertEqual(self.visitor.get("/write").status_code,302)
        self.assertEqual(self.visitor.get("/settings").status_code,302)

    def test_every_screen_renders(self):
        self.memory()
        self.post(self.owner,"/anniversaries",dict(title="One time",day="2020-01-01"))
        for path in ("/","/anniversaries","/wishes","/todos","/settings","/trash","/write","/moments/1","/moments/1/edit"):
            self.assertEqual(self.owner.get(path).status_code,200,path)

    def test_todos_assign_filter_complete_archive_and_stay_private(self):
        self.join()
        with self.app.app_context():
            partner_id=self.app.extensions['love_db']().execute("SELECT id FROM accounts WHERE role='partner'").fetchone()[0]
        response=self.post(self.owner,'/todos',{'title':'私密野餐准备','project':'周末计划','notes':'准备野餐垫','due':'2025-01-01','priority':'1','assignee':str(partner_id)})
        self.assertEqual(response.status_code,302,response.data)
        self.assertIn('私密野餐准备',self.partner.get('/todos?filter=today').get_data(as_text=True))
        self.assertNotIn('私密野餐准备',self.visitor.get('/').get_data(as_text=True))
        self.assertNotIn('私密野餐准备',self.owner.get('/?view=public').get_data(as_text=True))
        self.assertEqual(self.visitor.get('/todos').status_code,302)
        self.assertEqual(self.partner.get('/todos/1/edit').status_code,403)
        self.post(self.partner,'/todos/1/toggle')
        self.assertIn('私密野餐准备',self.owner.get('/todos?filter=done').get_data(as_text=True))
        self.assertEqual(self.post(self.partner,'/todos/1/archive').status_code,403)
        self.post(self.owner,'/todos/1/archive')
        self.assertIn('私密野餐准备',self.owner.get('/todos?filter=archive').get_data(as_text=True))
        self.post(self.owner,'/todos/1/restore')
        self.assertEqual(self.owner.get('/todos/1/edit').status_code,200)
        bad=self.post(self.owner,'/todos',{'title':'bad','assignee':'9999'})
        self.assertEqual(bad.status_code,400)


class CountdownTests(unittest.TestCase):
    def test_next_occurrence_one_time_past_and_leap_day(self):
        self.assertEqual(countdown("2020-02-29",True,dt.date(2025,2,27))["days"],1)
        self.assertEqual(countdown("2020-02-29",True,dt.date(2025,2,28))["days"],0)
        self.assertEqual(countdown("2020-02-29",True,dt.date(2025,3,1))["target"],"2026-02-28")
        self.assertEqual(countdown("2025-01-01",False,dt.date(2025,1,2))["days"],-1)
        self.assertEqual(countdown("2028-01-01",True,dt.date(2025,1,2))["target"],"2028-01-01")
