import re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from secgate import RULES  # noqa: E402

SQL = re.compile(dict((r[0], r[2]) for r in RULES)["SQL_CONCAT"])

VULNERABLE = [
    'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
    'q = "SELECT * FROM users WHERE name = \'" + name + "\'"',
    '$r = DB::select("SELECT * FROM orders WHERE id = $id");',
    "$sql = 'DELETE FROM posts WHERE id = ' . $id;",
    'db.query(`UPDATE users SET role = ${role} WHERE id = 1`)',
    'cmd.CommandText = "INSERT INTO logs VALUES (\'" + msg + "\')";',
    'db.rawQuery("SELECT * FROM t WHERE x=" + value, null);',
]
SAFE = [
    'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
    "DB::select('SELECT * FROM orders WHERE id = ?', [$id]);",
    'return "updated" if p.returncode == 0 else f"install-failed rc={p.returncode}"',
    'print("Please select an option: " + name)',
    'status = "update check: " + status',
    'db.query("UPDATE users SET name = $1 WHERE id = $2", [n, id])',
]


def test_sql_concat_detects_built_queries():
    assert [s for s in VULNERABLE if not SQL.search(s)] == []


def test_sql_concat_ignores_safe_and_unrelated_lines():
    assert [s for s in SAFE if SQL.search(s)] == []
