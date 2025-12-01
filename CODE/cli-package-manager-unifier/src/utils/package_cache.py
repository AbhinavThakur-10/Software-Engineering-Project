"""
SQLite cache for installed packages.
"""
import sqlite3
import os
from typing import List, Tuple

DB_PATH = os.path.join(os.path.dirname(__file__), '../../package_cache.db')

class PackageCacheDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = os.path.abspath(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self._create_table()

    def _create_table(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS installed_packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    version TEXT,
                    manager TEXT,
                    UNIQUE(name, version, manager)
                )
            ''')

    def add_package(self, name: str, version: str, manager: str):
        with self.conn:
            self.conn.execute(
                'INSERT OR IGNORE INTO installed_packages (name, version, manager) VALUES (?, ?, ?)',
                (name, version, manager)
            )

    def get_packages(self) -> List[Tuple[str, str, str]]:
        cur = self.conn.cursor()
        cur.execute('SELECT name, version, manager FROM installed_packages')
        return cur.fetchall()

    def close(self):
        self.conn.close()
