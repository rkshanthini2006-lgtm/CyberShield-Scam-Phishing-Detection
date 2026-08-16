import os


class Config:

    SECRET_KEY = "CyberShield2026"

    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    DEBUG = True

    HOST = "127.0.0.1"

    PORT = 5000

    # =========================
    # MYSQL DATABASE
    # =========================

    MYSQL_HOST = "localhost"
    MYSQL_USER = "root"
    MYSQL_PASSWORD = "27Shan"
    MYSQL_DATABASE = "cybershield"