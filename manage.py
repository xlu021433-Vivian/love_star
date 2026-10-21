"""Local-only administrator creation; never put a password on the command line."""
import argparse
from getpass import getpass
import sqlite3
from lovestar import LoveError, create_app

parser=argparse.ArgumentParser(description="恋爱星本机管理")
parser.add_argument("command",choices=["init-admin"])
if __name__=="__main__":
    parser.parse_args()
    app=create_app()
    name=input("管理员用户名（1–10 字符）：")
    password=getpass("密码（8–15 字符，不会显示）：")
    if password!=getpass("再次输入密码："):
        raise SystemExit("两次密码不同，未创建账号。")
    try:
        with app.app_context():
            app.extensions["love_initialize_admin"](name,password)
    except LoveError as error:
        raise SystemExit(str(error))
    print("管理员已创建，可以启动服务后登录。")
