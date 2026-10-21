"""A single couple's private journal, with deliberately public memories."""
from contextlib import closing
import datetime as dt
import functools
import hashlib
import hmac
import io
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
import uuid
from zoneinfo import ZoneInfo

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, send_file, session, url_for
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
 id INTEGER PRIMARY KEY, username TEXT COLLATE BINARY UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','partner')),
 active INTEGER NOT NULL DEFAULT 1, version INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS one_owner ON accounts(role) WHERE role='admin';
CREATE UNIQUE INDEX IF NOT EXISTS one_partner ON accounts(role) WHERE role='partner' AND active=1;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS invitations (digest TEXT PRIMARY KEY,expires REAL NOT NULL,used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS limits (key TEXT PRIMARY KEY,attempts INTEGER NOT NULL,expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS moments (
 id INTEGER PRIMARY KEY,author_id INTEGER NOT NULL REFERENCES accounts(id),
 title TEXT NOT NULL,content TEXT NOT NULL,day TEXT NOT NULL,mood TEXT NOT NULL,
 public INTEGER NOT NULL DEFAULT 0,photo TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,updated_at TEXT NOT NULL,deleted_at TEXT);
CREATE INDEX IF NOT EXISTS moment_visibility ON moments(deleted_at,public,day DESC);
CREATE TABLE IF NOT EXISTS anniversaries (
 id INTEGER PRIMARY KEY,author_id INTEGER NOT NULL REFERENCES accounts(id),
 title TEXT NOT NULL,day TEXT NOT NULL,yearly INTEGER NOT NULL DEFAULT 1,public INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS wishes (
 id INTEGER PRIMARY KEY,author_id INTEGER NOT NULL REFERENCES accounts(id),
 title TEXT NOT NULL,done INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS todos (
 id INTEGER PRIMARY KEY,author_id INTEGER NOT NULL REFERENCES accounts(id),
 title TEXT NOT NULL,notes TEXT NOT NULL DEFAULT '',project TEXT NOT NULL DEFAULT '日常',
 due TEXT NOT NULL DEFAULT '',priority INTEGER NOT NULL DEFAULT 0,assignee_id INTEGER REFERENCES accounts(id),
 done INTEGER NOT NULL DEFAULT 0,archived INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL);
"""
USERNAME = re.compile(r"[A-Za-z0-9_一-鿿.-]{1,10}\Z")
MOODS = {"heart":"心动", "daily":"小日常", "date":"约会", "travel":"出走一下", "gift":"小惊喜", "rain":"一起撑伞"}


class LoveError(ValueError):
    pass


def today():
    return dt.datetime.now(ZoneInfo("Asia/Shanghai")).date()


def valid_day(value):
    try:
        result = dt.date.fromisoformat(value)
        if not 1900 <= result.year <= 2100:
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise LoveError("请选择 1900–2100 年之间的有效日期。")


def countdown(day, yearly, current=None):
    current = current or today()
    original = valid_day(day)
    target = original
    if yearly:
        def in_year(year):
            try:
                return original.replace(year=year)
            except ValueError:
                return dt.date(year, 2, 28)
        target = in_year(max(current.year, original.year))
        if target < current:
            target = in_year(current.year + 1)
    return {"target":target.isoformat(), "days":(target-current).days}


def _key(root):
    path = root / "secret.key"
    if not path.exists():
        temporary = root / (".key-" + uuid.uuid4().hex)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(secrets.token_hex(32)); stream.flush(); os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            temporary.unlink(missing_ok=True)
    value = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[a-f0-9]{64}",value):
        raise RuntimeError("恋爱星会话密钥无效，请恢复备份中的 secret.key。")
    return value


def create_app(data_dir=None, cookie_path="/", secure=None, testing=False):
    app = Flask(__name__)
    root = Path(data_dir or os.environ.get("LOVE_DATA_DIR", Path(__file__).resolve().parent.parent / "data")).resolve()
    root.mkdir(parents=True,exist_ok=True)
    uploads = root / "uploads"; uploads.mkdir(exist_ok=True)
    key = _key(root)
    app.config.update(SECRET_KEY=key, TESTING=testing, MAX_CONTENT_LENGTH=9*1024*1024,
        SESSION_COOKIE_NAME="love_star_session",SESSION_COOKIE_PATH=cookie_path,
        SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(os.environ.get("LOVE_HTTPS")=="1") if secure is None else secure,
        PERMANENT_SESSION_LIFETIME=dt.timedelta(days=14))
    dummy = generate_password_hash(secrets.token_urlsafe(24))

    def db():
        if "love_db" not in g:
            g.love_db = sqlite3.connect(root / "love.db",timeout=10)
            g.love_db.row_factory = sqlite3.Row
            g.love_db.execute("PRAGMA foreign_keys=ON")
        return g.love_db

    @app.teardown_appcontext
    def close_db(error=None):
        conn = g.pop("love_db",None)
        if conn is not None:
            conn.close()

    def stamp(account):
        value = account["password_hash"] + ":" + str(account["version"])
        return hmac.new(key.encode(),value.encode(),hashlib.sha256).hexdigest()

    def reserve(name,limit=30,seconds=60):
        name = hmac.new(key.encode(),name.encode(),hashlib.sha256).hexdigest()
        now=time.time(); conn=db()
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM limits WHERE expires<=?",(now,))
            row=conn.execute("SELECT * FROM limits WHERE key=?",(name,)).fetchone()
            if row and row["attempts"]>=limit:
                abort(429,description="操作有些频繁，请稍后再试。")
            conn.execute("INSERT INTO limits VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET attempts=excluded.attempts,expires=excluded.expires",
                         (name,(row["attempts"] if row else 0)+1,row["expires"] if row else now+seconds))

    def csrf_token():
        if "csrf" not in session:
            session["csrf"]=secrets.token_urlsafe(32)
        return session["csrf"]

    @app.before_request
    def identity_and_csrf():
        g.account=None
        g.public_preview=False
        account=db().execute("SELECT * FROM accounts WHERE id=? AND active=1",(session.get("love_uid"),)).fetchone()
        if account and account["role"]=="admin" and hmac.compare_digest(stamp(account),str(session.get("love_stamp",""))):
            g.account=account
        if request.endpoint is None:
            abort(404)
        if request.endpoint not in {'static','login','logout'} and not g.account:
            if request.endpoint=='media' or request.method!='GET':
                abort(404)
            return redirect(url_for('login'))
        if request.method in {"POST","PUT","PATCH","DELETE"}:
            supplied=request.headers.get("X-CSRF-Token") or request.form.get("_csrf","")
            if not session.get("csrf") or not hmac.compare_digest(session["csrf"],supplied):
                abort(400,description="页面已过期，请刷新后重试。")
            if g.account:
                reserve("write:"+str(g.account["id"]))

    def member_only(admin=False):
        def decorate(view):
            @functools.wraps(view)
            def wrapped(*args,**kwargs):
                if not g.account:
                    return redirect(url_for("login"))
                if admin and g.account["role"]!="admin":
                    abort(403)
                return view(*args,**kwargs)
            return wrapped
        return decorate

    def profile():
        if not g.account: return {}
        values={r["key"]:r["value"] for r in db().execute("SELECT * FROM settings")}
        # Never place private profile values in a visitor's rendered HTML.
        if (not g.account or g.public_preview) and values.get("public_profile")!="1":
            return {}
        return values

    @app.context_processor
    def context():
        csrf_token()
        return dict(account=g.account,public_preview=g.public_preview,csrf_token=csrf_token,profile=profile(),moods=MOODS,today=today().isoformat(),
                    configured=bool(db().execute("SELECT 1 FROM accounts WHERE role='admin'").fetchone()))

    @app.after_request
    def headers(response):
        if request.endpoint!="static":
            response.headers["Cache-Control"]="private, no-store"
            response.vary.add("Cookie")
            response.headers["X-Robots-Tag"]="noindex, nofollow"
        response.headers["X-Content-Type-Options"]="nosniff"
        response.headers["Referrer-Policy"]="same-origin"
        response.headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        return response

    @app.errorhandler(LoveError)
    def invalid(error):
        return render_template("love_error.html",code=400,message=str(error)),400

    for status in (400,403,404,413,429):
        def handler(error):
            messages={400:"页面或输入无效，请检查后重试。",403:"这一步需要管理员权限。",404:"这颗星暂时没有向你亮起。",413:"照片请控制在 8 MB 以内。",429:"操作有些频繁，请稍后再试。"}
            return render_template("love_error.html",code=error.code,message=messages[error.code]),error.code
        app.register_error_handler(status,handler)

    def credentials(name,password):
        if not USERNAME.fullmatch(name) or not 8<=len(password)<=15:
            raise LoveError("用户名 1–10 个字符，区分大小写；密码 8–15 个字符。")

    def initialize_admin(name,password):
        credentials(name,password)
        password_hash=generate_password_hash(password)
        with db():
            db().execute("BEGIN IMMEDIATE")
            if db().execute("SELECT 1 FROM accounts WHERE role='admin'").fetchone():
                raise LoveError("管理员已经存在，请直接登录恋爱星。")
            db().execute("INSERT INTO accounts(username,password_hash,role) VALUES(?,?,'admin')",(name,password_hash))

    @app.route("/login",methods=["GET","POST"])
    def login():
        if g.account:
            return redirect(url_for("index"))
        if request.method=="POST":
            name,password=request.form.get("username",""),request.form.get("password","")
            reserve("login-ip:"+(request.remote_addr or "unknown"),10,300)
            if len(name)>100 or len(password)>128:
                raise LoveError("用户名或密码不正确。")
            account=db().execute("SELECT * FROM accounts WHERE username=? AND active=1",(name,)).fetchone()
            valid=check_password_hash(account["password_hash"] if account else dummy,password)
            if account and valid and account["role"]=="admin":
                session.clear();session.permanent=True
                session.update(love_uid=account["id"],love_stamp=stamp(account))
                return redirect(url_for("index"))
            flash("用户名或密码不正确，或账号已被停用。")
        return render_template("love_auth.html",joining=False)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    def visible_where():
        return "deleted_at IS NULL"

    @app.get("/")
    def index():
        where=visible_where();params=[]
        query=request.args.get("q","").strip()[:100]
        if query:
            where+=" AND (instr(title,?)>0 OR instr(content,?)>0)";params.extend([query,query])
        on_this_day=request.args.get("today")=="1"
        if on_this_day:
            where+=" AND substr(day,6)=?";params.append(today().strftime("%m-%d"))
        raw_page=request.args.get("page","1")
        page=min(100000,max(1,int(raw_page))) if raw_page.isascii() and raw_page.isdigit() and len(raw_page)<7 else 1
        count=db().execute("SELECT COUNT(*) FROM moments WHERE "+where,params).fetchone()[0]
        page=min(page,max(1,(count+11)//12))
        moments=db().execute("SELECT m.*,a.username FROM moments m JOIN accounts a ON a.id=m.author_id WHERE "+where+" ORDER BY day DESC,id DESC LIMIT 12 OFFSET ?",(*params,(page-1)*12)).fetchall()
        days=None; milestone=None; values=profile()
        if values.get("start_day"):
            start=valid_day(values["start_day"]);days=max(1,(today()-start).days+1)
            target=next((n for n in (100,365,520,730,1000,1314,2000,3000,5000,10000) if n>days),((days//1000)+1)*1000)
            milestone=dict(target=target,left=target-days,date=(start+dt.timedelta(days=target-1)).isoformat())
        upcoming=[{**dict(row),**countdown(row["day"],row["yearly"])} for row in db().execute("SELECT * FROM anniversaries"+("" if g.account and not g.public_preview else " WHERE public=1"))]
        upcoming.sort(key=lambda item:(item["days"]<0,abs(item["days"])))
        tasks=[]; task_count=0
        if g.account and not g.public_preview:
            tasks=db().execute("SELECT * FROM todos WHERE done=0 AND archived=0 ORDER BY CASE WHEN due='' THEN 1 ELSE 0 END,due,priority DESC,id DESC LIMIT 3").fetchall()
            task_count=db().execute('SELECT COUNT(*) FROM todos WHERE done=0 AND archived=0').fetchone()[0]
        return render_template("love_index.html",moments=moments,count=count,page=page,pages=max(1,(count+11)//12),query=query,
                               on_this_day=on_this_day,days=days,milestone=milestone,upcoming=upcoming[:2],tasks=tasks,task_count=task_count)

    def moment(book_id,editing=False,deleted=False):
        row=db().execute("SELECT m.*,a.username FROM moments m JOIN accounts a ON a.id=m.author_id WHERE m.id=?",(book_id,)).fetchone()
        if not row or bool(row["deleted_at"])!=deleted or (not g.account and not row["public"]):
            abort(404)
        if editing and (not g.account or (g.account["role"]!="admin" and row["author_id"]!=g.account["id"])):
            abort(403)
        return row

    @app.get("/moments/<int:moment_id>")
    def detail(moment_id):
        return render_template("love_detail.html",moment=moment(moment_id))

    @app.get("/media/<photo>")
    def media(photo):
        if not re.fullmatch(r"[a-f0-9]{32}\.jpg",photo):
            abort(404)
        row=db().execute("SELECT id FROM moments WHERE photo=? AND "+visible_where(),(photo,)).fetchone()
        if not row or not (uploads/photo).is_file():
            abort(404)
        return send_file(uploads/photo,mimetype="image/jpeg",conditional=False,max_age=0)

    def store_photo(upload):
        if not upload or not upload.filename:
            return ""
        raw=upload.read(8*1024*1024+1)
        if len(raw)>8*1024*1024:
            raise LoveError("照片请控制在 8 MB 以内。")
        if sum(p.stat().st_size for p in uploads.glob("*.jpg"))>200*1024*1024:
            raise LoveError("照片空间已达到 200 MB，请联系站主备份整理。")
        try:
            with Image.open(io.BytesIO(raw)) as image:
                if image.format not in {"JPEG","PNG","WEBP"} or image.width*image.height>25_000_000:
                    raise LoveError("请选择不超过 2500 万像素的 JPG、PNG 或 WebP 照片。")
                image=ImageOps.exif_transpose(image)
                image.thumbnail((2048,2048))
                clean=Image.new("RGB",image.size,"white")
                if image.mode in ("RGBA","LA") or "transparency" in image.info:
                    rgba=image.convert("RGBA");clean.paste(rgba,mask=rgba.getchannel("A"))
                else:
                    clean.paste(image.convert("RGB"))
                filename=uuid.uuid4().hex+".jpg"
                clean.save(uploads/filename,format="JPEG",quality=88)
                return filename
        except (UnidentifiedImageError,OSError,Image.DecompressionBombError,ValueError) as error:
            if isinstance(error,LoveError):
                raise
            raise LoveError("这张照片暂时无法读取，请换一张试试。") from error

    @app.route("/write",methods=["GET","POST"])
    @app.route("/moments/<int:moment_id>/edit",methods=["GET","POST"])
    @member_only()
    def write(moment_id=None):
        row=moment(moment_id,editing=True) if moment_id else None
        if request.method=="POST":
            title=request.form.get("title","").strip();content=request.form.get("content","").strip()
            day=valid_day(request.form.get("day","")).isoformat();mood=request.form.get("mood","daily")
            if not 1<=len(title)<=100 or not 1<=len(content)<=10000 or mood not in MOODS:
                raise LoveError("标题 1–100 字，正文 1–10000 字，请选择有效的心情。")
            if not row and db().execute("SELECT COUNT(*) FROM moments").fetchone()[0]>=1000:
                raise LoveError("记录已达到 1000 条，请先备份整理。")
            public=0
            photo=store_photo(request.files.get("photo")) or (row["photo"] if row else "")
            if request.form.get("remove_photo")=="1" and not request.files.get("photo"):
                photo=""
            stamp_now=dt.datetime.now(dt.timezone.utc).isoformat()
            with db():
                if row:
                    db().execute("UPDATE moments SET title=?,content=?,day=?,mood=?,public=?,photo=?,updated_at=? WHERE id=?",
                                 (title,content,day,mood,public,photo,stamp_now,row["id"]))
                    result_id=row["id"]
                else:
                    cursor=db().execute("INSERT INTO moments(author_id,title,content,day,mood,public,photo,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                                  (g.account["id"],title,content,day,mood,public,photo,stamp_now,stamp_now))
                    result_id=cursor.lastrowid
            flash("这一天，已经好好留下了。" + (" 目前公开可见。" if public else " 仅你们两人可见。"))
            return redirect(url_for("detail",moment_id=result_id))
        return render_template("love_write.html",moment=row)

    @app.post("/moments/<int:moment_id>/trash")
    @member_only()
    def trash_moment(moment_id):
        moment(moment_id,editing=True)
        with db():
            db().execute("UPDATE moments SET deleted_at=? WHERE id=?",(dt.datetime.now(dt.timezone.utc).isoformat(),moment_id))
        flash("已移入回收站，可随时恢复。")
        return redirect(url_for("index"))

    @app.get("/trash")
    @member_only()
    def trash():
        clause="" if g.account["role"]=="admin" else " AND author_id=?"
        rows=db().execute("SELECT * FROM moments WHERE deleted_at IS NOT NULL"+clause+" ORDER BY id DESC",() if not clause else (g.account["id"],)).fetchall()
        return render_template("love_trash.html",moments=rows)

    @app.post("/moments/<int:moment_id>/restore")
    @member_only()
    def restore(moment_id):
        moment(moment_id,editing=True,deleted=True)
        with db():
            # Restores start private, even if the old entry used to be public.
            db().execute("UPDATE moments SET deleted_at=NULL,public=0 WHERE id=?",(moment_id,))
        return redirect(url_for("detail",moment_id=moment_id))

    @app.route("/anniversaries",methods=["GET","POST"])
    @app.route("/anniversaries/<int:item_id>/edit",methods=["GET","POST"])
    def anniversaries(item_id=None):
        editing=None
        if item_id:
            if not g.account:
                abort(404)
            editing=db().execute("SELECT * FROM anniversaries WHERE id=?",(item_id,)).fetchone()
            if not editing or (g.account["role"]!="admin" and editing["author_id"]!=g.account["id"]):
                abort(403)
        if request.method=="POST":
            if not g.account:
                abort(403)
            title=request.form.get("title","").strip();day=valid_day(request.form.get("day","")).isoformat()
            if not 1<=len(title)<=80:
                raise LoveError("纪念日名称请控制在 1–80 个字。")
            if not editing and db().execute("SELECT COUNT(*) FROM anniversaries").fetchone()[0]>=100:
                raise LoveError("最多保留 100 个纪念日。")
            public=0
            with db():
                if editing:
                    db().execute("UPDATE anniversaries SET title=?,day=?,yearly=?,public=? WHERE id=?",(title,day,int(request.form.get("yearly")=="1"),public,item_id))
                else:
                    db().execute("INSERT INTO anniversaries(author_id,title,day,yearly,public) VALUES(?,?,?,?,?)",(g.account["id"],title,day,int(request.form.get("yearly")=="1"),public))
            return redirect(url_for("anniversaries"))
        rows=[{**dict(row),**countdown(row["day"],row["yearly"])} for row in db().execute("SELECT * FROM anniversaries"+("" if g.account else " WHERE public=1"))]
        rows.sort(key=lambda item:(item["days"]<0,abs(item["days"])))
        return render_template("love_anniversaries.html",anniversaries=rows,editing=editing)

    @app.post("/anniversaries/<int:item_id>/hide")
    @member_only()
    def hide_anniversary(item_id):
        row=db().execute("SELECT * FROM anniversaries WHERE id=?",(item_id,)).fetchone()
        if not row or (g.account["role"]!="admin" and row["author_id"]!=g.account["id"]):
            abort(404)
        with db():
            db().execute("UPDATE anniversaries SET public=0 WHERE id=?",(item_id,))
        return redirect(url_for("anniversaries"))

    @app.route("/wishes",methods=["GET","POST"])
    @member_only()
    def wishes():
        if request.method=="POST":
            title=request.form.get("title","").strip()
            if not 1<=len(title)<=150:
                raise LoveError("心愿请控制在 1–150 个字。")
            if db().execute("SELECT COUNT(*) FROM wishes").fetchone()[0]>=200:
                raise LoveError("最多保留 200 个共同心愿。")
            with db():
                db().execute("INSERT INTO wishes(author_id,title,updated_at) VALUES(?,?,?)",(g.account["id"],title,dt.datetime.now(dt.timezone.utc).isoformat()))
            return redirect(url_for("wishes"))
        rows=db().execute("SELECT * FROM wishes ORDER BY done,updated_at DESC,id DESC").fetchall()
        return render_template("love_wishes.html",wishes=rows)

    @app.post("/wishes/<int:item_id>/toggle")
    @member_only()
    def toggle_wish(item_id):
        with db():
            db().execute("UPDATE wishes SET done=1-done,updated_at=? WHERE id=?",(dt.datetime.now(dt.timezone.utc).isoformat(),item_id))
        return redirect(url_for("wishes"))

    @app.route('/todos',methods=['GET','POST'])
    @app.route('/todos/<int:item_id>/edit',methods=['GET','POST'])
    @member_only()
    def todos(item_id=None):
        editing=None
        if item_id:
            editing=db().execute('SELECT * FROM todos WHERE id=?',(item_id,)).fetchone()
            if not editing or (g.account['role']!='admin' and editing['author_id']!=g.account['id']):
                abort(403)
        if request.method=='POST':
            title=request.form.get('title','').strip();notes=request.form.get('notes','').strip()
            project=request.form.get('project','日常').strip() or '日常';due=request.form.get('due','').strip()
            priority=request.form.get('priority','0');assignee=request.form.get('assignee','')
            if not 1<=len(title)<=150 or len(notes)>2000 or len(project)>30 or priority not in ('0','1'):
                raise LoveError('待办名称 1–150 字，备注最多 2000 字，项目名最多 30 字。')
            if due: due=valid_day(due).isoformat()
            target=None
            if assignee:
                if not assignee.isascii() or not assignee.isdigit() or len(assignee)>10:
                    raise LoveError('请选择有效的负责人。')
                target=db().execute('SELECT id FROM accounts WHERE id=? AND active=1 AND role="admin"',(int(assignee),)).fetchone()
                if not target: raise LoveError('这个账号当前不可分配待办。')
                target=target['id']
            with db():
                if not editing and db().execute('SELECT COUNT(*) FROM todos WHERE archived=0').fetchone()[0]>=500:
                    raise LoveError('最多保留 500 项待办，请先归档已完成的项目。')
                values=(title,notes,project,due,int(priority),target,dt.datetime.now(dt.timezone.utc).isoformat())
                if editing:
                    db().execute('UPDATE todos SET title=?,notes=?,project=?,due=?,priority=?,assignee_id=?,updated_at=? WHERE id=?',(*values,item_id))
                else:
                    db().execute('INSERT INTO todos(title,notes,project,due,priority,assignee_id,updated_at,author_id) VALUES(?,?,?,?,?,?,?,?)',(*values,g.account['id']))
            return redirect(url_for('todos'))
        selected=request.args.get('filter','open');project=request.args.get('project','')[:30]
        clauses={'open':'t.done=0 AND archived=0','today':"t.done=0 AND archived=0 AND due<>'' AND due<=?",'done':'t.done=1 AND archived=0','archive':'archived=1'}
        where=clauses.get(selected,clauses['open']);params=[today().isoformat()] if selected=='today' else []
        if project: where+=' AND project=?';params.append(project)
        rows=db().execute('SELECT t.*,a.username AS assignee FROM todos t LEFT JOIN accounts a ON a.id=t.assignee_id WHERE '+where+" ORDER BY priority DESC,CASE WHEN due='' THEN 1 ELSE 0 END,due,id DESC",params).fetchall()
        people=db().execute("SELECT id,username FROM accounts WHERE active=1 AND role='admin'").fetchall()
        projects=[r[0] for r in db().execute('SELECT DISTINCT project FROM todos WHERE archived=0 ORDER BY project')]
        return render_template('love_todos.html',tasks=rows,editing=editing,people=people,projects=projects,selected=selected,project=project)

    @app.post('/todos/<int:item_id>/<action>')
    @member_only()
    def todo_action(item_id,action):
        row=db().execute('SELECT * FROM todos WHERE id=?',(item_id,)).fetchone()
        if not row: abort(404)
        if action not in ('toggle','archive','restore'): abort(404)
        if action!='toggle' and g.account['role']!='admin' and row['author_id']!=g.account['id']: abort(403)
        with db():
            if action=='toggle': db().execute('UPDATE todos SET done=1-done,updated_at=? WHERE id=?',(dt.datetime.now(dt.timezone.utc).isoformat(),item_id))
            else: db().execute('UPDATE todos SET archived=? WHERE id=?',(int(action=='archive'),item_id))
        return redirect(url_for('todos',filter='archive' if action=='restore' else 'open'))

    @app.route("/settings",methods=["GET","POST"])
    @member_only(admin=True)
    def settings():
        if request.method=="POST":
            values={name:request.form.get(name,"").strip() for name in ("name_one","name_two","start_day")}
            if any(len(values[name])>20 for name in ("name_one","name_two")):
                raise LoveError("昵称最多 20 个字。")
            if values["start_day"] and valid_day(values["start_day"])>today():
                raise LoveError("在一起的第一天不能晚于今天。")
            values["public_profile"]="0"
            with db():
                db().executemany("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",values.items())
            flash("星球设置已保存。")
            return redirect(url_for("settings"))
        return render_template("love_settings.html")

    with app.app_context():
        db().execute("PRAGMA journal_mode=WAL")
        db().executescript(SCHEMA);db().commit()
    app.extensions.update(love_db=db,love_initialize_admin=initialize_admin,love_data_dir=root)
    return app
