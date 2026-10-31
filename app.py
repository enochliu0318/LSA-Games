#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校运会成绩管理系统 —— 后端
运行:  python app.py            (默认监听 0.0.0.0:8000,局域网内其他设备可访问)
       python app.py --port 8080
       python app.py --reset-password   (重置管理员密码)
"""
import os, sys, json, random, secrets, socket, io, csv, hashlib, sqlite3, math, time, shutil
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g, Response, send_file

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, 'data')
os.makedirs(DATA, exist_ok=True)
DB_PATH = os.path.join(DATA, 'meet.db')

app = Flask(__name__, static_folder=os.path.join(BASE, 'static'), static_url_path='/static')
app.json.ensure_ascii = False
STATE = {'v': int(time.time() * 1000)}      # 数据版本号:任何写操作后递增,前端据此自动刷新
SESS = {}                                   # token -> {'role','user','name','uid'}

# ----------------------------------------------------------------- 数据库
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS teams(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, color TEXT DEFAULT '#2563eb',
  parent_id INTEGER REFERENCES teams(id) ON DELETE SET NULL, sort INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS athletes(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, gender TEXT DEFAULT 'M', bib TEXT,
  team_id INTEGER REFERENCES teams(id) ON DELETE SET NULL, note TEXT, grade TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'track',
  gender TEXT DEFAULT 'X', grp TEXT, start_time TEXT, duration INTEGER DEFAULT 20,
  venue TEXT, lanes INTEGER DEFAULT 8, status TEXT DEFAULT 'scheduled',
  scored INTEGER DEFAULT 1, points_json TEXT, record_value REAL, record_holder TEXT,
  bonus REAL, note TEXT);
CREATE TABLE IF NOT EXISTS heats(
  id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  name TEXT, start_time TEXT, sort INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS entries(
  id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  athlete_id INTEGER REFERENCES athletes(id) ON DELETE CASCADE,
  team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
  label TEXT, members TEXT, heat_id INTEGER REFERENCES heats(id) ON DELETE SET NULL,
  lane INTEGER, seed REAL, value REAL, status TEXT DEFAULT 'reg');
CREATE UNIQUE INDEX IF NOT EXISTS ux_entry_ath ON entries(event_id, athlete_id) WHERE athlete_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_entry_event ON entries(event_id);
CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY, ts TEXT, role TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS recorders(
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT, pw TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS recorder_events(
  recorder_id INTEGER NOT NULL REFERENCES recorders(id) ON DELETE CASCADE,
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  PRIMARY KEY(recorder_id, event_id));
"""

DEFAULTS = {
    'meet_name': 'LSA Games',
    'points_individual': [9, 7, 6, 5, 4, 3, 2, 1],
    'points_relay': [18, 14, 12, 10, 8, 6, 4, 2],
    'participation': 1,       # 完赛参与分(每个有效成绩计一次)
    'record_bonus': 5,        # 破纪录加分(可被项目覆盖)
    'max_events': 3,          # 每人最多报名项目数(超出需强制)
    'lanes': 8,
    'heat_gap': 5,            # 相邻分组间隔(分钟)
}


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


@app.teardown_appcontext
def _close(_):
    d = g.pop('db', None)
    if d:
        d.close()


def init_db():
    c = sqlite3.connect(DB_PATH)
    c.execute('PRAGMA journal_mode=WAL')
    c.executescript(SCHEMA)
    if 'grade' not in [r[1] for r in c.execute('PRAGMA table_info(athletes)')]:
        c.execute('ALTER TABLE athletes ADD COLUMN grade TEXT')
    c.commit()
    c.close()


def settings():
    S = dict(DEFAULTS)
    for r in db().execute("SELECT key,value FROM settings WHERE key NOT LIKE 'pw_%'"):
        try:
            S[r['key']] = json.loads(r['value'])
        except Exception:
            pass
    return S


def put_setting(key, val):
    db().execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, json.dumps(val, ensure_ascii=False)))


def get_raw(key):
    r = db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return json.loads(r['value']) if r else None


def log(action, detail=''):
    db().execute("INSERT INTO log(ts,role,action,detail) VALUES(?,?,?,?)",
                 (datetime.now().strftime('%m-%d %H:%M:%S'), who(), action, detail[:300]))


# ----------------------------------------------------------------- 权限
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(4)
    return salt + '$' + hashlib.sha256((salt + pw).encode()).hexdigest()


def check_pw(pw, stored):
    if not stored or '$' not in stored:
        return False
    salt = stored.split('$')[0]
    return secrets.compare_digest(hash_pw(pw, salt), stored)


def sess():
    return SESS.get(request.cookies.get('tok') or request.headers.get('X-Token'))


def role():
    s = sess()
    return s['role'] if s else None


def who():
    s = sess()
    return s['user'] if s else '-'


def can_record(eid):
    """管理员可录入所有项目;录入员只能录入被分配给自己的项目。"""
    s = sess()
    if not s:
        return False
    if s['role'] == 'admin':
        return True
    return db().execute("SELECT 1 FROM recorder_events WHERE recorder_id=? AND event_id=?",
                        (s['uid'], eid)).fetchone() is not None


def deny_event():
    return jsonify(error='你的账号没有该项目的录入权限'), 403


LEVEL = {'recorder': 1, 'admin': 2}


def need(level):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            r = role()
            if not r or LEVEL[r] < LEVEL[level]:
                return jsonify(error='需要%s权限,请先登录' % ('管理员' if level == 'admin' else '录入员')), 403
            return f(*a, **k)
        return w
    return deco


@app.after_request
def _after(resp):
    if request.method != 'GET' and resp.status_code < 400 and request.path != '/api/login':
        STATE['v'] = int(time.time() * 1000)
    resp.headers['Cache-Control'] = 'public, max-age=86400' if request.path.startswith('/static/fonts/') else 'no-store'
    return resp


@app.errorhandler(ValueError)
def _bad(e):
    return jsonify(error=str(e)), 400


@app.errorhandler(Exception)
def _err(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify(error=e.description), e.code
    app.logger.exception(e)
    return jsonify(error='服务器错误: %s' % e), 500


@app.post('/api/login')
def login():
    p = request.get_json(silent=True) or {}
    u, pw = (p.get('username') or '').strip(), p.get('password', '')
    sd = None
    if u == '' or u.lower() == 'admin':
        if check_pw(pw, get_raw('pw_admin')):
            sd = dict(role='admin', user='admin', name='管理员', uid=None)
    else:
        r = db().execute("SELECT * FROM recorders WHERE username=?", (u,)).fetchone()
        if r and check_pw(pw, r['pw']):
            sd = dict(role='recorder', user=r['username'], name=r['name'] or r['username'], uid=r['id'])
    if not sd:
        time.sleep(0.6)
        return jsonify(error='账号或密码错误'), 401
    tok = secrets.token_urlsafe(16)
    SESS[tok] = sd
    resp = jsonify(role=sd['role'], user=sd['user'], name=sd['name'])
    resp.set_cookie('tok', tok, max_age=7 * 86400, httponly=True, samesite='Lax')
    return resp


@app.post('/api/logout')
def logout():
    SESS.pop(request.cookies.get('tok'), None)
    resp = jsonify(ok=True)
    resp.delete_cookie('tok')
    return resp


# ----------------------------------------------------------------- 成绩解析 / 计分
def parse_value(txt):
    s = str(txt if txt is not None else '').strip().replace('：', ':').replace('。', '.').replace('，', '.')
    if s == '':
        return None
    try:
        if ':' in s:
            v = 0.0
            for p in s.split(':'):
                v = v * 60 + float(p)
            return round(v, 3)
        return round(float(s), 3)
    except ValueError:
        raise ValueError('无法识别的成绩: %s' % txt)


def fmt_value(v, kind):
    if v is None:
        return ''
    if kind == 'field':
        return '%.2f' % v
    if v >= 60:
        m = int(v // 60)
        return '%d:%05.2f' % (m, v - 60 * m)
    return '%.2f' % v


def better(a, b, kind):  # a 是否优于 b
    return a < b if kind != 'field' else a > b


def entry_rows(d, eid):
    return [dict(r) for r in d.execute("""
        SELECT e.*, a.name AS athlete_name, a.gender AS athlete_gender, a.bib,
               COALESCE(e.team_id, a.team_id) AS tid, t.name AS team_name, t.color AS team_color,
               h.name AS heat_name, h.sort AS heat_sort
        FROM entries e LEFT JOIN athletes a ON a.id=e.athlete_id
        LEFT JOIN teams t ON t.id=COALESCE(e.team_id,a.team_id)
        LEFT JOIN heats h ON h.id=e.heat_id
        WHERE e.event_id=?
        ORDER BY COALESCE(h.sort,999), COALESCE(e.lane,999), e.id""", (eid,))]


def compute(d, ev, S, rows=None):
    """返回该项目所有报名行(附排名/得分)。并列取名次区间平均分。"""
    rows = rows if rows is not None else entry_rows(d, ev['id'])
    kind = ev['kind']
    asc = kind != 'field'
    table = json.loads(ev['points_json']) if ev['points_json'] else (
        S['points_relay'] if kind == 'relay' else S['points_individual'])
    key = lambda r: round(r['value'], 2)
    valid = sorted([r for r in rows if r['status'] == 'ok' and r['value'] is not None],
                   key=(lambda r: key(r)) if asc else (lambda r: -key(r)))
    for r in rows:
        r.update(rank=None, points=0, part=0, bonus=0, record=False, total=0,
                 value_text=fmt_value(r['value'], kind) if r['status'] == 'ok' else '')
    i = 0
    while i < len(valid):
        j = i
        while j + 1 < len(valid) and key(valid[j + 1]) == key(valid[i]):
            j += 1
        pts = 0
        if ev['scored']:
            span = [table[k] if k < len(table) else 0 for k in range(i, j + 1)]
            pts = sum(span) / len(span)
        for k in range(i, j + 1):
            valid[k]['rank'] = i + 1
            valid[k]['points'] = pts
        i = j + 1
    if ev['scored']:
        bonus = ev['bonus'] if ev['bonus'] is not None else S['record_bonus']
        for r in valid:
            r['part'] = S['participation']
            if r['rank'] == 1 and ev['record_value'] is not None and better(r['value'], ev['record_value'], kind):
                r['record'] = True
                r['bonus'] = bonus
    for r in rows:
        r['total'] = r['points'] + r['part'] + r['bonus']
        if r['status'] not in ('reg', 'ok'):
            r['value_text'] = r['status']
    rows.sort(key=lambda r: (r['rank'] is None, r['rank'] or 0))
    return rows


def ev_dict(r):
    e = dict(r)
    e['points_list'] = json.loads(e['points_json']) if e.get('points_json') else None
    e['record_text'] = fmt_value(e['record_value'], e['kind']) if e.get('record_value') is not None else ''
    return e


def fmt_pts(x):
    return int(x) if float(x).is_integer() else round(x, 2)


# ----------------------------------------------------------------- 基础信息
def lan_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith('127.') and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


@app.get('/')
def index():
    return send_file(os.path.join(BASE, 'static', 'index.html'))


@app.get('/api/info')
def info():
    S = settings()
    port = request.host.split(':')[-1] if ':' in request.host else '80'
    sd = sess()
    mine = []
    if sd and sd['role'] == 'recorder':
        mine = [r['event_id'] for r in db().execute("SELECT event_id FROM recorder_events WHERE recorder_id=?", (sd['uid'],))]
    return jsonify(meet_name=S['meet_name'], version=STATE['v'], role=role(),
                   user=sd['user'] if sd else None, name=sd['name'] if sd else None, my_events=mine,
                   urls=['http://%s:%s' % (ip, port) for ip in lan_ips()])


@app.get('/api/version')
def version():
    return jsonify(v=STATE['v'])


@app.get('/api/qr.svg')
def qr():
    try:
        import segno
    except ImportError:
        return 'segno 未安装', 404
    buf = io.BytesIO()
    segno.make(request.args.get('u', ''), error='m').save(buf, kind='svg', scale=5, border=1)
    return Response(buf.getvalue(), mimetype='image/svg+xml')


@app.get('/api/settings')
def get_settings():
    return jsonify(settings())


@app.put('/api/settings')
@need('admin')
def set_settings():
    p = request.get_json() or {}
    d = db()
    for k in DEFAULTS:
        if k in p:
            v = p[k]
            if k.startswith('points_'):
                v = [float(x) for x in v]
            elif k != 'meet_name':
                v = float(v)
            put_setting(k, v)
    if p.get('admin_password'):
        if len(p['admin_password']) < 4:
            return jsonify(error='密码至少 4 位'), 400
        put_setting('pw_admin', hash_pw(p['admin_password']))
    log('改设置')
    d.commit()
    return jsonify(ok=True)


# ----------------------------------------------------------------- 队伍
@app.get('/api/teams')
def teams_list():
    d = db()
    rows = [dict(r) for r in d.execute("""
        SELECT t.*, (SELECT COUNT(*) FROM athletes a WHERE a.team_id=t.id) AS members
        FROM teams t ORDER BY sort, id""")]
    return jsonify(rows)


def team_body(p):
    name = (p.get('name') or '').strip()
    if not name:
        raise ValueError('队伍名称不能为空')
    return name, p.get('color') or '#2563eb', p.get('parent_id') or None


@app.post('/api/teams')
@need('admin')
def team_create():
    name, color, parent = team_body(request.get_json() or {})
    d = db()
    cur = d.execute("INSERT INTO teams(name,color,parent_id,sort) VALUES(?,?,?,(SELECT COALESCE(MAX(sort),0)+1 FROM teams))",
                    (name, color, parent))
    log('新建队伍', name)
    d.commit()
    return jsonify(id=cur.lastrowid)


@app.put('/api/teams/<int:tid>')
@need('admin')
def team_update(tid):
    name, color, parent = team_body(request.get_json() or {})
    if parent == tid:
        return jsonify(error='上级队伍不能是自己'), 400
    d = db()
    # 防止形成环
    p = parent
    while p:
        if p == tid:
            return jsonify(error='上级队伍不能是自己的下级'), 400
        r = d.execute("SELECT parent_id FROM teams WHERE id=?", (p,)).fetchone()
        p = r['parent_id'] if r else None
    d.execute("UPDATE teams SET name=?,color=?,parent_id=? WHERE id=?", (name, color, parent, tid))
    log('改队伍', name)
    d.commit()
    return jsonify(ok=True)


@app.delete('/api/teams/<int:tid>')
@need('admin')
def team_delete(tid):
    d = db()
    d.execute("DELETE FROM teams WHERE id=?", (tid,))
    log('删队伍', str(tid))
    d.commit()
    return jsonify(ok=True)


@app.post('/api/teams/auto-assign')
@need('admin')
def team_auto_assign():
    """把人员随机且均衡(可按性别分层)地分配到若干队伍。"""
    p = request.get_json() or {}
    ids = [int(x) for x in p.get('team_ids', [])]
    if len(ids) < 2:
        return jsonify(error='请至少选择两支队伍'), 400
    d = db()
    q = "SELECT id,gender,team_id FROM athletes"
    if p.get('only_unassigned', True):
        q += " WHERE team_id IS NULL"
    ath = [dict(r) for r in d.execute(q)]
    random.shuffle(ath)
    load = {t: d.execute("SELECT COUNT(*) FROM athletes WHERE team_id=?", (t,)).fetchone()[0] for t in ids}
    gl = {t: {'M': 0, 'F': 0} for t in ids}
    for r in d.execute("SELECT team_id,gender,COUNT(*) c FROM athletes WHERE team_id IN (%s) GROUP BY 1,2" % ','.join('?' * len(ids)), ids):
        gl[r['team_id']][r['gender'] if r['gender'] in ('M', 'F') else 'M'] += r['c']
    n = 0
    for a in ath:
        g_ = a['gender'] if a['gender'] in ('M', 'F') else 'M'
        if p.get('balance_gender', True):
            t = min(ids, key=lambda x: (gl[x][g_], load[x], random.random()))
        else:
            t = min(ids, key=lambda x: (load[x], random.random()))
        d.execute("UPDATE athletes SET team_id=? WHERE id=?", (t, a['id']))
        load[t] += 1
        gl[t][g_] += 1
        n += 1
    log('自动分队', '%d 人' % n)
    d.commit()
    return jsonify(assigned=n)


# ----------------------------------------------------------------- 人员
def norm_gender(g_):
    g_ = str(g_ or '').strip().upper()
    return 'F' if g_ in ('F', '女', 'FEMALE', 'W') else 'M'


def descendants(d, tid):
    out, stack = {tid}, [tid]
    while stack:
        cur = stack.pop()
        for r in d.execute("SELECT id FROM teams WHERE parent_id=?", (cur,)):
            if r['id'] not in out:
                out.add(r['id'])
                stack.append(r['id'])
    return out


@app.get('/api/athletes')
def athletes_list():
    d = db()
    q, args = ["1=1"], []
    if request.args.get('q'):
        q.append("(a.name LIKE ? OR a.bib LIKE ?)")
        args += ['%' + request.args['q'] + '%'] * 2
    if request.args.get('unassigned'):
        q.append("a.team_id IS NULL")
    if request.args.get('team_id'):
        ids = descendants(d, int(request.args['team_id']))
        q.append("a.team_id IN (%s)" % ','.join(map(str, ids)))
    if request.args.get('gender'):
        q.append("a.gender=?")
        args.append(request.args['gender'])
    if request.args.get('grade'):
        q.append("a.grade=?")
        args.append(request.args['grade'])
    rows = [dict(r) for r in d.execute("""
        SELECT a.*, t.name AS team_name, t.color AS team_color,
          (SELECT COUNT(*) FROM entries e WHERE e.athlete_id=a.id) AS n_events,
          (SELECT GROUP_CONCAT(e.event_id) FROM entries e WHERE e.athlete_id=a.id) AS event_ids,
          (SELECT GROUP_CONCAT(ev.name || COALESCE(ev.grp,''), '、') FROM entries e JOIN events ev ON ev.id=e.event_id WHERE e.athlete_id=a.id) AS event_names
        FROM athletes a LEFT JOIN teams t ON t.id=a.team_id
        WHERE %s ORDER BY (a.bib IS NULL), CAST(a.bib AS INTEGER), a.bib, a.id""" % ' AND '.join(q), args)]
    for r in rows:
        r['event_ids'] = [int(x) for x in r['event_ids'].split(',')] if r['event_ids'] else []
    return jsonify(rows)


@app.get('/api/grades')
def grades_list():
    return jsonify([r[0] for r in db().execute(
        "SELECT DISTINCT grade FROM athletes WHERE grade IS NOT NULL AND grade!='' ORDER BY grade")])


def _clean(v):
    v = (v or '').strip() if isinstance(v, str) or v is None else str(v).strip()
    return v or None


@app.post('/api/athletes')
@need('admin')
def athlete_create():
    p = request.get_json() or {}
    if not (p.get('name') or '').strip():
        return jsonify(error='姓名不能为空'), 400
    d = db()
    cur = d.execute("INSERT INTO athletes(name,gender,bib,team_id,note,grade) VALUES(?,?,?,?,?,?)",
                    (p['name'].strip(), norm_gender(p.get('gender')), _clean(p.get('bib')),
                     p.get('team_id') or None, p.get('note'), _clean(p.get('grade'))))
    log('新增人员', p['name'])
    d.commit()
    return jsonify(id=cur.lastrowid)


@app.put('/api/athletes/<int:aid>')
@need('admin')
def athlete_update(aid):
    p = request.get_json() or {}
    if not (p.get('name') or '').strip():
        return jsonify(error='姓名不能为空'), 400
    d = db()
    d.execute("UPDATE athletes SET name=?,gender=?,bib=?,team_id=?,note=?,grade=? WHERE id=?",
              (p['name'].strip(), norm_gender(p.get('gender')), _clean(p.get('bib')),
               p.get('team_id') or None, p.get('note'), _clean(p.get('grade')), aid))
    log('改人员', p['name'])
    d.commit()
    return jsonify(ok=True)


@app.put('/api/athletes/<int:aid>/events')
@need('admin')
def athlete_set_events(aid):
    """把该选手的个人项目报名设置为 event_ids(多退少补)。已有成绩的项目被取消时需 confirm_remove。"""
    p = request.get_json() or {}
    d = db()
    a = d.execute("SELECT * FROM athletes WHERE id=?", (aid,)).fetchone()
    if not a:
        return jsonify(error='人员不存在'), 404
    want = {int(x) for x in p.get('event_ids', [])}
    cur = {r['event_id']: dict(r) for r in d.execute(
        "SELECT * FROM entries WHERE athlete_id=?", (aid,))}
    rm = [e for e in cur if e not in want]
    lost = [e for e in rm if cur[e]['value'] is not None or cur[e]['status'] not in ('reg',)]
    if lost and not p.get('confirm_remove'):
        names = [r['name'] for r in d.execute("SELECT name FROM events WHERE id IN (%s)" % ','.join(map(str, lost)))]
        return jsonify(error='取消的项目中已有成绩/状态,将一并删除:' + '、'.join(names), need_confirm=True), 409
    for e in rm:
        d.execute("DELETE FROM entries WHERE id=?", (cur[e]['id'],))
    S = settings()
    warnings, added = [], 0
    for eid in want - set(cur):
        ev = d.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        if not ev or ev['kind'] == 'relay':
            continue
        d.execute("INSERT INTO entries(event_id,athlete_id) VALUES(?,?)", (eid, aid))
        added += 1
    for eid in want:
        ev = d.execute("SELECT name,grp,gender FROM events WHERE id=?", (eid,)).fetchone()
        if ev and ev['gender'] in ('M', 'F') and ev['gender'] != a['gender']:
            warnings.append('“%s%s”与选手性别不符' % (ev['name'], ev['grp'] or ''))
    if len(want) > S['max_events']:
        warnings.append('已报 %d 项,超过上限 %d 项' % (len(want), int(S['max_events'])))
    for c in find_conflicts(d):
        if c['aid'] == aid:
            warnings.append('时间冲突:%s(%s)与 %s(%s)' % (c['a'], c['at'], c['b'], c['bt']))
    log('改报名', '%s 共 %d 项' % (a['name'], len(want)))
    d.commit()
    return jsonify(added=added, removed=len(rm), warnings=warnings)


@app.post('/api/athletes/bulk-assign')
@need('admin')
def athlete_bulk_assign():
    p = request.get_json() or {}
    ids = [int(i) for i in p.get('ids', [])]
    d = db()
    d.executemany("UPDATE athletes SET team_id=? WHERE id=?", [(p.get('team_id') or None, i) for i in ids])
    log('批量分队', '%d 人' % len(ids))
    d.commit()
    return jsonify(updated=len(ids))


@app.post('/api/athletes/bulk-update')
@need('admin')
def athlete_bulk_update():
    """批量修改年级 / 队伍(请求里出现哪个字段就改哪个字段)。"""
    p = request.get_json() or {}
    ids = [int(i) for i in p.get('ids', [])]
    d = db()
    if 'grade' in p:
        d.executemany("UPDATE athletes SET grade=? WHERE id=?", [(_clean(p['grade']), i) for i in ids])
    if 'team_id' in p:
        d.executemany("UPDATE athletes SET team_id=? WHERE id=?", [(p['team_id'] or None, i) for i in ids])
    log('批量修改', '%d 人' % len(ids))
    d.commit()
    return jsonify(updated=len(ids))


@app.post('/api/athletes/delete-many')
@need('admin')
def athlete_delete_many():
    ids = [int(i) for i in (request.get_json() or {}).get('ids', [])]
    d = db()
    d.executemany("DELETE FROM athletes WHERE id=?", [(i,) for i in ids])
    log('批量删除人员', '%d 人' % len(ids))
    d.commit()
    return jsonify(deleted=len(ids))


def infer_kind(name):
    if '接力' in name:
        return 'relay'
    if any(k in name for k in ('跳', '掷', '铅球', '铁饼', '标枪', '链球', '实心球', '垒球', '投')):
        return 'field'
    return 'track'


HEAD_MAP = {'姓名': 'name', '名字': 'name', 'name': 'name', '性别': 'gender', 'gender': 'gender',
            '年级': 'grade', 'grade': 'grade', '班级': 'team', '队伍': 'team', '班级/队伍': 'team', '队': 'team',
            'team': 'team', '号码': 'bib', '编号': 'bib', '号码布': 'bib', 'bib': 'bib',
            '项目': 'events', '报名项目': 'events', '参赛项目': 'events', '参加项目': 'events', 'events': 'events',
            '组别': 'grp', '组': 'grp', '分组': 'grp', 'grp': 'grp',
            '备注': 'note', 'note': 'note'}
DEFAULT_COLS = ['name', 'gender', 'team', 'bib', 'grade', 'events', 'grp', 'note']


def split_line(line):
    if '\t' in line:                       # 从 Excel 直接粘贴
        return [x.strip() for x in line.split('\t')]
    try:
        return [x.strip() for x in next(csv.reader([line.replace('，', ',')]))]
    except Exception:
        return [x.strip() for x in line.replace('，', ',').split(',')]


@app.post('/api/athletes/import')
@need('admin')
def athlete_import():
    """批量导入人员(可同时导入报名项目)。
    有表头(含“姓名”列)时按表头识别列,列顺序任意;
    无表头时按固定顺序:姓名,性别,队伍,号码,年级,项目,组别,备注。
    项目不存在时按「项目+性别+组别」自动创建(create_events 为 False 时不创建)。
    “项目”列可写多个,用 、 ; | / 或逗号分隔(制表符粘贴时可含逗号)。
    """
    p = request.get_json() or {}
    d = db()
    teams = {r['name']: r['id'] for r in d.execute("SELECT id,name FROM teams")}
    evs = [dict(r) for r in d.execute("SELECT id,name,grp,kind,gender FROM events")]
    S = settings()
    stat = dict(imported=0, updated=0, new_teams=0, registered=0)
    skipped, warnings = [], []
    cols, first = list(DEFAULT_COLS), True

    created, relay_noted = [], set()

    def canon(tok, gender):
        """把“100米/男100米/男子100米/混合4×100米接力”规范成 (项目全名, 性别, 去掉性别的基础名)。"""
        t = tok.strip()
        for pre, g in (('男子', 'M'), ('女子', 'F'), ('混合', 'X'), ('男', 'M'), ('女', 'F')):
            if t.startswith(pre) and len(t) > len(pre):
                return {'M': '男子', 'F': '女子', 'X': '混合'}[g] + t[len(pre):], g, t[len(pre):]
        return ('男子' if gender == 'M' else '女子') + t, gender, t

    def find_event(tok, gender, grp):
        name, g, base = canon(tok, gender)
        for ev in evs:
            eg = ev['grp'] or ''
            if grp and eg != grp:
                continue
            if (ev['name'] == name and ev['gender'] in (g, 'X')) or tok in (ev['name'], ev['name'] + eg, eg + ev['name']):
                return ev
        if not p.get('create_events', True) or (g in ('M', 'F') and g != gender):
            return None
        kind = infer_kind(base)
        cur = d.execute("INSERT INTO events(%s) VALUES(%s)" % (EV_COLS, ','.join('?' * 15)),
                        (name, kind, g, grp or None, None, {'relay': 25, 'field': 60}.get(kind, 20),
                         None if kind == 'field' else '田径场', int(S['lanes']), 'scheduled', 1, None, None, None, None, None))
        ev = dict(id=cur.lastrowid, name=name, grp=grp or None, kind=kind, gender=g)
        evs.append(ev)
        created.append(name + (grp or ''))
        return ev

    for ln, line in enumerate((p.get('text') or '').splitlines(), 1):
        line = line.strip().lstrip('﻿')
        if not line:
            continue
        parts = split_line(line)
        if first:
            first = False
            mapped = [HEAD_MAP.get(x.replace(' ', '').lower()) for x in parts]
            if 'name' in mapped:
                cols = [m or '_' for m in mapped]
                continue
        row = {}
        for i, c in enumerate(cols):
            if c != '_' and i < len(parts) and parts[i]:
                row[c] = parts[i]
        if not row.get('name'):
            skipped.append('第%d行:缺少姓名' % ln)
            continue
        tid = None
        tname = row.get('team')
        if tname:
            if tname not in teams:
                if p.get('create_teams', True):
                    cur = d.execute("INSERT INTO teams(name,sort) VALUES(?,(SELECT COALESCE(MAX(sort),0)+1 FROM teams))", (tname,))
                    teams[tname] = cur.lastrowid
                    stat['new_teams'] += 1
                else:
                    skipped.append('第%d行:队伍“%s”不存在' % (ln, tname))
                    continue
            tid = teams[tname]
        ex = None
        if p.get('update_existing', True):
            if row.get('bib'):
                ex = d.execute("SELECT * FROM athletes WHERE bib=?", (row['bib'],)).fetchone()
            else:
                if tid:
                    found = d.execute("SELECT * FROM athletes WHERE name=? AND team_id=?", (row['name'], tid)).fetchall()
                else:   # 未写队伍:姓名唯一才视为同一个人
                    found = d.execute("SELECT * FROM athletes WHERE name=?", (row['name'],)).fetchall()
                if len(found) > 1:
                    skipped.append('第%d行:“%s”有多人重名,请填写队伍或号码以区分' % (ln, row['name']))
                    continue
                ex = found[0] if found else None
        if ex:
            aid = ex['id']
            gender = norm_gender(row['gender']) if row.get('gender') else ex['gender']
            d.execute("UPDATE athletes SET gender=?, grade=COALESCE(?,grade), bib=COALESCE(?,bib), team_id=COALESCE(?,team_id), note=COALESCE(?,note) WHERE id=?",
                      (gender, row.get('grade'), row.get('bib'), tid, row.get('note'), aid))
            stat['updated'] += 1
        else:
            gender = norm_gender(row.get('gender'))
            aid = d.execute("INSERT INTO athletes(name,gender,team_id,bib,grade,note) VALUES(?,?,?,?,?,?)",
                            (row['name'], gender, tid, row.get('bib'), row.get('grade'), row.get('note'))).lastrowid
            stat['imported'] += 1
        n_reg = d.execute("SELECT COUNT(*) FROM entries WHERE athlete_id=?", (aid,)).fetchone()[0]
        gsrc = p.get('group_by', 'auto')
        grp_val = None if gsrc == 'none' else (row.get('grade') if gsrc == 'grade' else row.get('grp'))
        for tok in [x.strip() for x in __import__('re').split(r'[、;；|/,，]+', row.get('events', '')) if x.strip()]:
            ev = find_event(tok, gender, grp_val)
            if not ev:
                warnings.append('第%d行 %s:找不到项目“%s”(或与性别不符)' % (ln, row['name'], tok))
            elif ev['kind'] == 'relay':
                if ev['id'] not in relay_noted:
                    relay_noted.add(ev['id'])
                    warnings.append('接力项目“%s”已创建/匹配,个人不会自动报名,请在项目页按队伍报名' % (ev['name'] + (ev['grp'] or '')))
            elif ev['gender'] in ('M', 'F') and ev['gender'] != gender:
                warnings.append('第%d行 %s:性别与项目“%s”不符,未报名' % (ln, row['name'], tok))
            else:
                c = d.execute("INSERT OR IGNORE INTO entries(event_id,athlete_id) VALUES(?,?)", (ev['id'], aid))
                if c.rowcount:
                    stat['registered'] += 1
                    n_reg += 1
        if n_reg > S['max_events']:
            warnings.append('第%d行 %s:共报 %d 项,超过上限 %d(已导入,请留意)' % (ln, row['name'], n_reg, int(S['max_events'])))
    log('导入人员', '新增%d 更新%d 报名%d' % (stat['imported'], stat['updated'], stat['registered']))
    d.commit()
    return jsonify(skipped=skipped, warnings=warnings, created_events=created, **stat)


@app.post('/api/athletes/assign-bibs')
@need('admin')
def assign_bibs():
    p = request.get_json() or {}
    start, pad = int(p.get('start', 1)), int(p.get('pad', 3))
    d = db()
    q = "SELECT a.id FROM athletes a LEFT JOIN teams t ON t.id=a.team_id"
    if not p.get('overwrite'):
        q += " WHERE a.bib IS NULL OR a.bib=''"
    q += " ORDER BY COALESCE(t.sort,9999), a.gender, a.name"
    ids = [r['id'] for r in d.execute(q)]
    used = {r['bib'] for r in d.execute("SELECT bib FROM athletes WHERE bib IS NOT NULL")} if not p.get('overwrite') else set()
    n = start
    for i in ids:
        while str(n).zfill(pad) in used:
            n += 1
        d.execute("UPDATE athletes SET bib=? WHERE id=?", (str(n).zfill(pad), i))
        n += 1
    d.commit()
    return jsonify(assigned=len(ids))


# ----------------------------------------------------------------- 项目
PRESETS = [  # (名称, 类型, 默认时长分钟)
    ('100米', 'track', 15), ('200米', 'track', 20), ('400米', 'track', 25), ('800米', 'track', 25),
    ('1500米', 'track', 25), ('4×100米接力', 'relay', 25),
    ('跳远', 'field', 60), ('铅球', 'field', 60), ('跳高', 'field', 60),
]


def event_body(p):
    name = (p.get('name') or '').strip()
    if not name:
        raise ValueError('项目名称不能为空')
    kind = p.get('kind') if p.get('kind') in ('track', 'field', 'relay') else 'track'
    pj = None
    if p.get('points_list'):
        pj = json.dumps([float(x) for x in p['points_list']])
    rv = parse_value(p.get('record_text')) if p.get('record_text') not in (None, '') else None
    bonus = float(p['bonus']) if p.get('bonus') not in (None, '') else None
    return (name, kind, p.get('gender') if p.get('gender') in ('M', 'F', 'X') else 'X', (p.get('grp') or '').strip() or None,
            (p.get('start_time') or '').strip() or None, int(p.get('duration') or 20), (p.get('venue') or '').strip() or None,
            int(p.get('lanes') or 8), p.get('status') if p.get('status') in ('scheduled', 'running', 'done') else 'scheduled',
            1 if p.get('scored', 1) else 0, pj, rv, (p.get('record_holder') or '').strip() or None, bonus, p.get('note'))


EV_COLS = "name,kind,gender,grp,start_time,duration,venue,lanes,status,scored,points_json,record_value,record_holder,bonus,note"


@app.get('/api/events')
def events_list():
    d = db()
    rows = []
    for r in d.execute("""SELECT ev.*,
        (SELECT COUNT(*) FROM entries e WHERE e.event_id=ev.id) AS n_entries,
        (SELECT COUNT(*) FROM entries e WHERE e.event_id=ev.id AND e.status='ok') AS n_done,
        (SELECT COUNT(*) FROM heats h WHERE h.event_id=ev.id) AS n_heats
        FROM events ev ORDER BY COALESCE(start_time,'9999'), id"""):
        rows.append(ev_dict(r))
    return jsonify(rows)


@app.post('/api/events')
@need('admin')
def event_create():
    b = event_body(request.get_json() or {})
    d = db()
    cur = d.execute("INSERT INTO events(%s) VALUES(%s)" % (EV_COLS, ','.join('?' * 15)), b)
    log('新建项目', b[0])
    d.commit()
    return jsonify(id=cur.lastrowid)


@app.post('/api/events/presets')
@need('admin')
def event_presets():
    p = request.get_json() or {}
    S = settings()
    d = db()
    genders = p.get('genders') or ['M', 'F']
    n = 0
    for g_ in genders:
        for name, kind, dur in PRESETS:
            d.execute("INSERT INTO events(%s) VALUES(%s)" % (EV_COLS, ','.join('?' * 15)),
                      (('男子' if g_ == 'M' else '女子' if g_ == 'F' else '') + name, kind, g_, p.get('grp') or None,
                       None, dur, '田径场' if kind != 'field' else None, int(S['lanes']), 'scheduled', 1, None, None, None, None, None))
            n += 1
    log('添加常用项目', str(n))
    d.commit()
    return jsonify(created=n)


@app.get('/api/events/<int:eid>')
def event_get(eid):
    d = db()
    ev = d.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev:
        return jsonify(error='项目不存在'), 404
    S = settings()
    rows = compute(d, ev, S)
    # 展示顺序:按分组+跑道
    rows_sorted = sorted(rows, key=lambda r: (r['heat_sort'] if r['heat_sort'] is not None else 999,
                                             r['lane'] or 999, r['bib'] or '', r['id']))
    heats = [dict(h) for h in d.execute("SELECT * FROM heats WHERE event_id=? ORDER BY sort,id", (eid,))]
    return jsonify(event=ev_dict(ev), entries=rows_sorted, heats=heats,
                   points_table=ev_dict(ev)['points_list'] or (S['points_relay'] if ev['kind'] == 'relay' else S['points_individual']))


@app.put('/api/events/<int:eid>')
@need('admin')
def event_update(eid):
    b = event_body(request.get_json() or {})
    d = db()
    old = d.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    d.execute("UPDATE events SET %s WHERE id=?" % ','.join(c + '=?' for c in EV_COLS.split(',')), b + (eid,))
    if old and old['start_time'] != b[4]:
        set_event_start(d, old, b[4])
    log('改项目', b[0])
    d.commit()
    return jsonify(ok=True)


@app.put('/api/events/<int:eid>/status')
@need('recorder')
def event_status(eid):
    if not can_record(eid):
        return deny_event()
    st = (request.get_json() or {}).get('status')
    if st not in ('scheduled', 'running', 'done'):
        return jsonify(error='状态无效'), 400
    d = db()
    d.execute("UPDATE events SET status=? WHERE id=?", (st, eid))
    d.commit()
    return jsonify(ok=True)


@app.delete('/api/events/<int:eid>')
@need('admin')
def event_delete(eid):
    d = db()
    d.execute("DELETE FROM events WHERE id=?", (eid,))
    log('删项目', str(eid))
    d.commit()
    return jsonify(ok=True)


# ----------------------------------------------------------------- 项目批量管理
TFMT = '%Y-%m-%d %H:%M'


def _dt(x):
    try:
        return datetime.strptime(x, TFMT)
    except (TypeError, ValueError):
        return None


def set_event_start(d, ev, new):
    """修改项目开始时间,并同步平移已生成的分组时间。new 为 'YYYY-MM-DD HH:MM' 或 None。"""
    old_t, new_t = _dt(ev['start_time']), _dt(new)
    heats = d.execute("SELECT id,start_time,sort FROM heats WHERE event_id=? ORDER BY sort,id", (ev['id'],)).fetchall()
    if new_t and old_t:
        delta = new_t - old_t
        for h in heats:
            ht = _dt(h['start_time'])
            if ht:
                d.execute("UPDATE heats SET start_time=? WHERE id=?", ((ht + delta).strftime(TFMT), h['id']))
    elif new_t and ev['kind'] != 'field':
        gap = int(settings()['heat_gap'])
        for k, h in enumerate(heats):
            d.execute("UPDATE heats SET start_time=? WHERE id=?", ((new_t + timedelta(minutes=k * gap)).strftime(TFMT), h['id']))
    elif not new_t:
        d.execute("UPDATE heats SET start_time=NULL WHERE event_id=?", (ev['id'],))
    d.execute("UPDATE events SET start_time=? WHERE id=?", (new_t.strftime(TFMT) if new_t else None, ev['id']))


@app.post('/api/events/bulk-update')
@need('admin')
def events_bulk_update():
    """批量修改:只改 fields 里出现的字段;shift_minutes 为整体平移开始时间。"""
    p = request.get_json() or {}
    ids = [int(i) for i in p.get('ids', [])]
    f = p.get('fields') or {}
    shift = int(p.get('shift_minutes') or 0)
    if 'start_time' in f and f['start_time'] and not _dt(f['start_time']):
        raise ValueError('开始时间格式不对')
    d = db()
    n = 0
    for eid in ids:
        ev = d.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        if not ev:
            continue
        sets, args = [], []
        for k in ('venue', 'grp', 'note'):
            if k in f:
                sets.append(k + '=?')
                args.append((f[k] or '').strip() or None)
        if f.get('duration'):
            sets.append('duration=?')
            args.append(max(1, int(f['duration'])))
        if f.get('lanes'):
            sets.append('lanes=?')
            args.append(min(12, max(1, int(f['lanes']))))
        if f.get('status') in ('scheduled', 'running', 'done'):
            sets.append('status=?')
            args.append(f['status'])
        if f.get('gender') in ('M', 'F', 'X'):
            sets.append('gender=?')
            args.append(f['gender'])
        if 'scored' in f and f['scored'] in (0, 1, '0', '1'):
            sets.append('scored=?')
            args.append(int(f['scored']))
        if sets:
            d.execute("UPDATE events SET %s WHERE id=?" % ','.join(sets), args + [eid])
        if 'start_time' in f:
            set_event_start(d, ev, (f['start_time'] or '').strip() or None)
        elif shift and _dt(ev['start_time']):
            set_event_start(d, ev, (_dt(ev['start_time']) + timedelta(minutes=shift)).strftime(TFMT))
        n += 1
    log('批量修改项目', '%d 个' % n)
    d.commit()
    return jsonify(updated=n)


@app.post('/api/events/bulk-delete')
@need('admin')
def events_bulk_delete():
    ids = [int(i) for i in (request.get_json() or {}).get('ids', [])]
    d = db()
    d.executemany("DELETE FROM events WHERE id=?", [(i,) for i in ids])
    log('批量删除项目', '%d 个' % len(ids))
    d.commit()
    return jsonify(deleted=len(ids))


@app.post('/api/events/bulk-heats')
@need('admin')
def events_bulk_heats():
    p = request.get_json() or {}
    d = db()
    S = settings()
    ok, skipped = 0, []
    for eid in [int(i) for i in p.get('ids', [])]:
        ev = d.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        if not ev:
            continue
        n = make_heats(d, ev, S, p.get('mode', 'random'), p.get('lanes'), p.get('gap'))
        if n is None:
            skipped.append(ev['name'] + (ev['grp'] or ''))
        else:
            ok += 1
    d.commit()
    return jsonify(generated=ok, skipped=skipped)


@app.post('/api/events/auto-schedule')
@need('admin')
def events_auto_schedule():
    """按 ids 的顺序依次排开始时间。per_venue=True 时每个场地各排一条时间线(不同场地可同时进行)。"""
    p = request.get_json() or {}
    start = _dt((p.get('start') or '').strip())
    if not start:
        raise ValueError('请填写起始时间')
    gap = int(p.get('gap') if p.get('gap') not in (None, '') else 5)
    per_venue = bool(p.get('per_venue', True))
    d = db()
    clock, n = {}, 0
    for eid in [int(i) for i in p.get('ids', [])]:
        ev = d.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        if not ev:
            continue
        key = (ev['venue'] or '') if per_venue else ''
        t = clock.get(key, start)
        set_event_start(d, ev, t.strftime(TFMT))
        clock[key] = t + timedelta(minutes=(ev['duration'] or 20) + gap)
        n += 1
    log('自动排时间', '%d 个项目' % n)
    d.commit()
    return jsonify(scheduled=n)


# ----------------------------------------------------------------- 报名
@app.post('/api/events/<int:eid>/entries')
@need('admin')
def entries_add(eid):
    p = request.get_json() or {}
    d = db()
    ev = d.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev:
        return jsonify(error='项目不存在'), 404
    S = settings()
    if ev['kind'] == 'relay':
        if not p.get('team_id'):
            return jsonify(error='接力项目请选择队伍'), 400
        d.execute("INSERT INTO entries(event_id,team_id,label,members) VALUES(?,?,?,?)",
                  (eid, int(p['team_id']), p.get('label') or None, p.get('members') or None))
        d.commit()
        return jsonify(added=1)
    added, warns = 0, []
    force = bool(p.get('force'))
    for aid in p.get('athlete_ids', []):
        a = d.execute("SELECT * FROM athletes WHERE id=?", (aid,)).fetchone()
        if not a:
            continue
        if ev['gender'] in ('M', 'F') and a['gender'] != ev['gender'] and not force:
            warns.append('%s 性别与项目不符' % a['name'])
            continue
        cnt = d.execute("SELECT COUNT(*) FROM entries WHERE athlete_id=?", (aid,)).fetchone()[0]
        if cnt >= S['max_events'] and not force:
            warns.append('%s 已报 %d 项(上限 %d)' % (a['name'], cnt, S['max_events']))
            continue
        try:
            d.execute("INSERT INTO entries(event_id,athlete_id) VALUES(?,?)", (eid, aid))
            added += 1
        except sqlite3.IntegrityError:
            warns.append('%s 已报名' % a['name'])
    log('报名', '%s +%d' % (ev['name'], added))
    d.commit()
    return jsonify(added=added, warnings=warns)


@app.put('/api/entries/<int:xid>')
@need('admin')
def entry_update(xid):
    """调整分组/跑道(目标位置已有人则两人互换)、报名成绩、接力队员。"""
    p = request.get_json() or {}
    d = db()
    e = d.execute("SELECT * FROM entries WHERE id=?", (xid,)).fetchone()
    if not e:
        return jsonify(error='报名记录不存在'), 404
    heat, lane = p.get('heat_id', e['heat_id']), p.get('lane', e['lane'])
    heat = int(heat) if heat else None
    lane = int(lane) if lane not in (None, '') else None
    if heat and lane:
        occ = d.execute("SELECT * FROM entries WHERE heat_id=? AND lane=? AND id!=?", (heat, lane, xid)).fetchone()
        if occ:
            d.execute("UPDATE entries SET heat_id=?, lane=? WHERE id=?", (e['heat_id'], e['lane'], occ['id']))
    seed = parse_value(p['seed']) if 'seed' in p else e['seed']
    d.execute("UPDATE entries SET heat_id=?,lane=?,seed=?,label=?,members=? WHERE id=?",
              (heat, lane, seed, p.get('label', e['label']), p.get('members', e['members']), xid))
    d.commit()
    return jsonify(ok=True)


@app.delete('/api/entries/<int:xid>')
@need('admin')
def entry_delete(xid):
    d = db()
    d.execute("DELETE FROM entries WHERE id=?", (xid,))
    d.commit()
    return jsonify(ok=True)


# ----------------------------------------------------------------- 分组与跑道
def lane_priority(L):
    a = (L + 1) // 2
    order, lo, hi = [], a, a + 1
    while len(order) < L:
        if lo >= 1:
            order.append(lo)
            lo -= 1
        if hi <= L and len(order) < L:
            order.append(hi)
            hi += 1
        if lo < 1 and hi > L:
            break
    return order


def make_heats(d, ev, S, mode='random', lanes=None, gap=None):
    """为项目重新生成分组与跑道。没有报名返回 None,否则返回组数。"""
    eid = ev['id']
    L = int(lanes or ev['lanes'] or S['lanes'])
    gap = int(gap if gap not in (None, '') else S['heat_gap'])
    ents = [dict(r) for r in d.execute("SELECT * FROM entries WHERE event_id=? AND status!='DNS'", (eid,))]
    if not ents:
        return None
    d.execute("UPDATE entries SET heat_id=NULL, lane=NULL WHERE event_id=?", (eid,))
    d.execute("DELETE FROM heats WHERE event_id=?", (eid,))
    asc = ev['kind'] != 'field'
    if mode == 'seed':   # 按报名成绩:差 → 好
        # 无报名成绩者视为最差;asc(越小越好)时最差在前,field(越大越好)时最差在前
        ents.sort(key=(lambda r: -(r['seed'] if r['seed'] is not None else 1e9)) if asc
                  else (lambda r: r['seed'] if r['seed'] is not None else -1e9))
    else:
        random.shuffle(ents)
    t0 = None
    if ev['start_time']:
        try:
            t0 = datetime.strptime(ev['start_time'], '%Y-%m-%d %H:%M')
        except ValueError:
            t0 = None
    groups = []
    if ev['kind'] == 'field':
        groups = [ents]
    else:
        n = len(ents)
        h = math.ceil(n / L)
        base, extra = divmod(n, h)
        pos = 0
        for i in range(h):          # 靠前的组人数多 1,最后一组(最强)放最后
            size = base + (1 if i < extra else 0)
            groups.append(ents[pos:pos + size])
            pos += size
    prio = lane_priority(L)
    for gi, g_ in enumerate(groups):
        name = '全体' if ev['kind'] == 'field' else ('决赛' if len(groups) == 1 else '第%d组' % (gi + 1))
        st = (t0 + timedelta(minutes=gi * gap)).strftime('%Y-%m-%d %H:%M') if (t0 and ev['kind'] != 'field') else None
        hid = d.execute("INSERT INTO heats(event_id,name,start_time,sort) VALUES(?,?,?,?)", (eid, name, st, gi)).lastrowid
        if ev['kind'] != 'field' and mode == 'seed':
            g_ = list(reversed(g_))  # 组内成绩最好者排在最前,占据最佳跑道
        for k, e in enumerate(g_):
            lane = (k + 1) if ev['kind'] == 'field' else prio[k]
            d.execute("UPDATE entries SET heat_id=?, lane=? WHERE id=?", (hid, lane, e['id']))
    log('生成分组', '%s %d 组' % (ev['name'], len(groups)))
    return len(groups)


@app.post('/api/events/<int:eid>/heats/generate')
@need('admin')
def heats_generate(eid):
    p = request.get_json() or {}
    d = db()
    ev = d.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    n = make_heats(d, ev, settings(), p.get('mode', 'random'), p.get('lanes'), p.get('gap'))
    if n is None:
        return jsonify(error='该项目还没有报名'), 400
    d.commit()
    return jsonify(heats=n)


@app.put('/api/heats/<int:hid>')
@need('admin')
def heat_update(hid):
    p = request.get_json() or {}
    d = db()
    d.execute("UPDATE heats SET name=?, start_time=? WHERE id=?",
              ((p.get('name') or '').strip() or None, (p.get('start_time') or '').strip() or None, hid))
    d.commit()
    return jsonify(ok=True)


# ----------------------------------------------------------------- 成绩录入
@app.post('/api/events/<int:eid>/results')
@need('recorder')
def results_save(eid):
    if not can_record(eid):
        return deny_event()
    p = request.get_json() or {}
    d = db()
    ev = d.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev:
        return jsonify(error='项目不存在'), 404
    try:
        for it in p.get('items', []):
            e = d.execute("SELECT id FROM entries WHERE id=? AND event_id=?", (it['entry_id'], eid)).fetchone()
            if not e:
                continue
            st = it.get('status') or 'ok'
            if st in ('ok', 'reg'):
                v = parse_value(it.get('value'))
                if v is not None and v <= 0:
                    raise ValueError('成绩必须大于 0')
                st = 'ok' if v is not None else 'reg'
            elif st in ('DNS', 'DNF', 'DQ', 'NM'):
                v = None
            else:
                raise ValueError('状态无效: %s' % st)
            d.execute("UPDATE entries SET value=?, status=? WHERE id=?", (v, st, e['id']))
    except ValueError as ex:
        d.rollback()
        return jsonify(error=str(ex)), 400
    log('录入成绩', '%s ×%d' % (ev['name'], len(p.get('items', []))))
    d.commit()
    rows = compute(d, ev, settings())
    return jsonify(entries=[{k: r[k] for k in ('id', 'rank', 'points', 'part', 'bonus', 'total', 'record', 'value_text', 'status')} for r in rows])


# ----------------------------------------------------------------- 积分榜 / 时间表
def depth_map(teams):
    byid = {t['id']: t for t in teams}
    out = {}
    for t in teams:
        n, p, seen = 0, t['parent_id'], set()
        while p and p in byid and p not in seen:
            seen.add(p)
            n += 1
            p = byid[p]['parent_id']
        out[t['id']] = n
    return out


@app.get('/api/board')
def board():
    d = db()
    S = settings()
    teams = [dict(r) for r in d.execute("SELECT id,name,color,parent_id,sort FROM teams ORDER BY sort,id")]
    dm = depth_map(teams)
    tm = {t['id']: dict(t, depth=dm[t['id']], pts=0, part=0, bonus=0, children=[]) for t in teams}
    events, breakdown = [], []
    total_ev, done_ev = 0, 0
    for ev in d.execute("SELECT * FROM events ORDER BY COALESCE(start_time,'9999'), id"):
        rows = compute(d, ev, S)
        total_ev += 1
        done_ev += 1 if ev['status'] == 'done' else 0
        ok = [r for r in rows if r['rank'] is not None]
        for r in ok:
            if r['tid'] in tm:
                tm[r['tid']]['pts'] += r['points']
                tm[r['tid']]['part'] += r['part']
                tm[r['tid']]['bonus'] += r['bonus']
                if r['total']:
                    breakdown.append(dict(team_id=r['tid'], event_id=ev['id'], event=ev['name'] + (ev['grp'] or ''),
                                          who=r['athlete_name'] or r['label'] or r['team_name'], rank=r['rank'],
                                          value=r['value_text'], points=fmt_pts(r['points']), part=fmt_pts(r['part']),
                                          bonus=fmt_pts(r['bonus'])))
        if ok:
            events.append(dict(id=ev['id'], name=ev['name'], grp=ev['grp'], status=ev['status'], kind=ev['kind'],
                               n_done=len(ok), n_entries=len(rows),
                               podium=[dict(rank=r['rank'], name=r['athlete_name'] or r['label'] or r['team_name'],
                                            team=r['team_name'], color=r['team_color'], value=r['value_text'],
                                            record=r['record'], bib=r['bib'])
                                       for r in ok if r['rank'] <= 3]))
    # 向上汇总:自己 + 所有下级
    for t in tm.values():
        t['own'] = {'pts': t['pts'], 'part': t['part'], 'bonus': t['bonus']}
    order = sorted(tm.values(), key=lambda t: -t['depth'])
    agg = {t['id']: dict(t['own']) for t in tm.values()}
    for t in order:
        if t['parent_id'] in agg and t['parent_id'] != t['id']:
            for k in ('pts', 'part', 'bonus'):
                agg[t['parent_id']][k] += agg[t['id']][k]
    out = []
    for t in teams:
        a, o = agg[t['id']], tm[t['id']]['own']
        out.append(dict(t, depth=dm[t['id']], total=fmt_pts(sum(a.values())), pts=fmt_pts(a['pts']), part=fmt_pts(a['part']),
                        bonus=fmt_pts(a['bonus']), own_total=fmt_pts(sum(o.values())),
                        has_children=any(x['parent_id'] == t['id'] for x in teams)))
    return jsonify(teams=out, events=events, breakdown=breakdown, total_events=total_ev, done_events=done_ev,
                   meet_name=S['meet_name'])


@app.get('/api/schedule')
def schedule():
    d = db()
    evs = []
    for r in d.execute("""SELECT ev.*, (SELECT COUNT(*) FROM entries e WHERE e.event_id=ev.id) AS n_entries,
        (SELECT COUNT(*) FROM heats h WHERE h.event_id=ev.id) AS n_heats
        FROM events ev ORDER BY COALESCE(start_time,'9999'), id"""):
        e = ev_dict(r)
        e['end_time'] = None
        if e['start_time']:
            try:
                e['end_time'] = (datetime.strptime(e['start_time'], '%Y-%m-%d %H:%M') + timedelta(minutes=e['duration'] or 20)).strftime('%H:%M')
            except ValueError:
                pass
        evs.append(e)
    return jsonify(events=evs, conflicts=find_conflicts(d), now=datetime.now().strftime('%Y-%m-%d %H:%M'))


def find_conflicts(d):
    evs = {}
    for r in d.execute("SELECT id,name,grp,start_time,duration FROM events WHERE start_time IS NOT NULL"):
        try:
            s = datetime.strptime(r['start_time'], '%Y-%m-%d %H:%M')
        except ValueError:
            continue
        evs[r['id']] = (s, s + timedelta(minutes=r['duration'] or 20), r['name'] + (r['grp'] or ''))
    by_ath = {}
    for r in d.execute("""SELECT e.athlete_id, e.event_id, a.name, a.bib, t.name AS team FROM entries e
                          JOIN athletes a ON a.id=e.athlete_id LEFT JOIN teams t ON t.id=a.team_id
                          WHERE e.event_id IN (%s)""" % (','.join(map(str, evs)) or '0')):
        by_ath.setdefault(r['athlete_id'], dict(aid=r['athlete_id'], name=r['name'], bib=r['bib'], team=r['team'], ev=[]))['ev'].append(r['event_id'])
    out = []
    for a in by_ath.values():
        ids = a['ev']
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                A, B = evs[ids[i]], evs[ids[j]]
                if A[0] < B[1] and B[0] < A[1]:
                    out.append(dict(aid=a['aid'], name=a['name'], bib=a['bib'], team=a['team'], a=A[2], b=B[2],
                                    at=A[0].strftime('%m-%d %H:%M'), bt=B[0].strftime('%m-%d %H:%M')))
    return out


# ----------------------------------------------------------------- 录入员账号(按项目授权)
def _gen_pw():
    return '%06d' % random.SystemRandom().randrange(1000000)


def _rec_events(d, rid):
    return [r['event_id'] for r in d.execute("SELECT event_id FROM recorder_events WHERE recorder_id=? ORDER BY event_id", (rid,))]


def _set_rec_events(d, rid, ids):
    d.execute("DELETE FROM recorder_events WHERE recorder_id=?", (rid,))
    for eid in {int(x) for x in ids}:
        if d.execute("SELECT 1 FROM events WHERE id=?", (eid,)).fetchone():
            d.execute("INSERT INTO recorder_events(recorder_id,event_id) VALUES(?,?)", (rid, eid))


def _kick(rid):
    for t in [t for t, x in SESS.items() if x.get('uid') == rid]:
        SESS.pop(t, None)


def _check_username(d, u, rid=None):
    import re
    if not u or not re.fullmatch(r'[A-Za-z0-9_\-\u4e00-\u9fa5]{1,24}', u):
        raise ValueError('账号只能由字母、数字、下划线、短横线或汉字组成(最长 24 位)')
    if u.lower() == 'admin':
        raise ValueError('“admin”是管理员账号,请换一个')
    r = d.execute("SELECT id FROM recorders WHERE username=?", (u,)).fetchone()
    if r and r['id'] != rid:
        raise ValueError('账号“%s”已存在' % u)


@app.get('/api/recorders')
@need('admin')
def rec_list():
    d = db()
    return jsonify([dict(id=r['id'], username=r['username'], name=r['name'], event_ids=_rec_events(d, r['id']))
                    for r in d.execute("SELECT * FROM recorders ORDER BY id")])


@app.post('/api/recorders')
@need('admin')
def rec_create():
    p = request.get_json() or {}
    d = db()
    u = (p.get('username') or '').strip()
    _check_username(d, u)
    pw = (p.get('password') or '').strip()
    if not pw:
        pw = _gen_pw()
    elif len(pw) < 4:
        raise ValueError('密码至少 4 位')
    cur = d.execute("INSERT INTO recorders(username,name,pw) VALUES(?,?,?)", (u, (p.get('name') or '').strip() or None, hash_pw(pw)))
    _set_rec_events(d, cur.lastrowid, p.get('event_ids', []))
    log('新建录入员', u)
    d.commit()
    return jsonify(id=cur.lastrowid, username=u, password=pw)


@app.put('/api/recorders/<int:rid>')
@need('admin')
def rec_update(rid):
    p = request.get_json() or {}
    d = db()
    r = d.execute("SELECT * FROM recorders WHERE id=?", (rid,)).fetchone()
    if not r:
        return jsonify(error='账号不存在'), 404
    u = (p.get('username') or r['username']).strip()
    kick = False
    if u != r['username']:
        _check_username(d, u, rid)
        kick = True
    new_pw = None
    if p.get('reset'):
        new_pw = _gen_pw()
    elif (p.get('password') or '').strip():
        new_pw = p['password'].strip()
        if len(new_pw) < 4:
            raise ValueError('密码至少 4 位')
    if new_pw:
        d.execute("UPDATE recorders SET pw=? WHERE id=?", (hash_pw(new_pw), rid))
        kick = True
    d.execute("UPDATE recorders SET username=?, name=? WHERE id=?", (u, (p.get('name') or '').strip() or None, rid))
    if 'event_ids' in p:
        _set_rec_events(d, rid, p['event_ids'])
    if kick:
        _kick(rid)
    log('改录入员', u)
    d.commit()
    return jsonify(ok=True, password=new_pw)


@app.delete('/api/recorders/<int:rid>')
@need('admin')
def rec_delete(rid):
    d = db()
    d.execute("DELETE FROM recorders WHERE id=?", (rid,))
    _kick(rid)
    log('删录入员', str(rid))
    d.commit()
    return jsonify(ok=True)


@app.post('/api/recorders/auto')
@need('admin')
def rec_auto():
    """为项目一键生成录入员账号:每个项目一个账号(r01、r02…),随机 6 位密码。密码只在此刻返回一次。"""
    p = request.get_json() or {}
    d = db()
    evs = [dict(r) for r in d.execute("SELECT id,name,grp FROM events ORDER BY COALESCE(start_time,'9999'), id")]
    seq = {e['id']: i + 1 for i, e in enumerate(evs)}
    if p.get('event_ids') is not None:
        want = {int(x) for x in p['event_ids']}
    else:
        have = {r['event_id'] for r in d.execute("SELECT event_id FROM recorder_events")}
        want = {e['id'] for e in evs if e['id'] not in have}
    out = []
    for e in evs:
        if e['id'] not in want:
            continue
        base, n = 'r%02d' % seq[e['id']], 1
        u = base
        while d.execute("SELECT 1 FROM recorders WHERE username=?", (u,)).fetchone():
            n += 1
            u = '%s_%d' % (base, n)
        pw = _gen_pw()
        label = e['name'] + (e['grp'] or '')
        rid = d.execute("INSERT INTO recorders(username,name,pw) VALUES(?,?,?)", (u, label, hash_pw(pw))).lastrowid
        _set_rec_events(d, rid, [e['id']])
        out.append(dict(username=u, password=pw, name=label))
    log('批量生成录入员', '%d 个' % len(out))
    d.commit()
    return jsonify(created=out)


# ----------------------------------------------------------------- 导出 / 备份 / 日志
def csv_response(name, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return Response('﻿' + buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': "attachment; filename*=UTF-8''%s" % __import__('urllib.parse').parse.quote(name)})


@app.get('/api/export/results.csv')
def export_results():
    d, S = db(), settings()
    rows = []
    for ev in d.execute("SELECT * FROM events ORDER BY COALESCE(start_time,'9999'), id"):
        for r in compute(d, ev, S):
            rows.append([ev['name'], ev['grp'] or '', r['heat_name'] or '', r['lane'] or '', r['bib'] or '',
                         r['athlete_name'] or r['label'] or '', r['team_name'] or '', r['value_text'], r['rank'] or '',
                         fmt_pts(r['points']), fmt_pts(r['part']), fmt_pts(r['bonus']), '是' if r['record'] else ''])
    return csv_response('项目成绩明细.csv', ['项目', '组别', '分组', '跑道/顺序', '号码', '姓名/接力队', '队伍', '成绩', '名次', '名次分', '参与分', '破纪录加分', '破纪录'], rows)


@app.get('/api/export/scores.csv')
def export_scores():
    b = board().get_json()
    return csv_response('团体总分.csv', ['层级', '队伍', '总分', '名次分', '参与分', '破纪录加分'],
                        [[t['depth'], t['name'], t['total'], t['pts'], t['part'], t['bonus']] for t in sorted(b['teams'], key=lambda t: -t['total'])])


@app.get('/api/export/schedule.csv')
def export_schedule():
    s = schedule().get_json()
    return csv_response('时间表.csv', ['开始', '结束', '项目', '组别', '场地', '时长(分)', '报名数', '状态'],
                        [[e['start_time'] or '', e['end_time'] or '', e['name'], e['grp'] or '', e['venue'] or '', e['duration'],
                          e['n_entries'], {'scheduled': '未开始', 'running': '进行中', 'done': '已结束'}[e['status']]] for e in s['events']])


@app.get('/api/export/athletes.csv')
def export_athletes():
    rows = athletes_list().get_json()
    return csv_response('人员名单.csv', ['号码', '姓名', '性别', '年级', '班级/队伍', '报名项目'],
                        [[a['bib'] or '', a['name'], '女' if a['gender'] == 'F' else '男', a['grade'] or '', a['team_name'] or '', (a['event_names'] or '')] for a in rows])


@app.get('/api/backup')
@need('admin')
def backup():
    os.makedirs(os.path.join(DATA, 'backups'), exist_ok=True)
    path = os.path.join(DATA, 'backups', 'meet-%s.db' % datetime.now().strftime('%Y%m%d-%H%M%S'))
    dst = sqlite3.connect(path)
    db().backup(dst)
    dst.close()
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@app.get('/api/log')
@need('admin')
def get_log():
    return jsonify([dict(r) for r in db().execute("SELECT ts,role,action,detail FROM log ORDER BY id DESC LIMIT 80")])


@app.post('/api/reset')
@need('admin')
def reset_all():
    p = request.get_json() or {}
    d = db()
    if p.get('confirm') != 'RESET':
        return jsonify(error='缺少确认'), 400
    path = os.path.join(DATA, 'backups')
    os.makedirs(path, exist_ok=True)
    dst = sqlite3.connect(os.path.join(path, 'before-reset-%s.db' % datetime.now().strftime('%Y%m%d-%H%M%S')))
    d.backup(dst)
    dst.close()
    for t in ('entries', 'heats', 'events', 'athletes', 'teams', 'recorders', 'log'):
        d.execute("DELETE FROM %s" % t)
    d.commit()
    return jsonify(ok=True)


@app.post('/api/demo')
@need('admin')
def demo():
    """载入演示数据,用于赛前试用(仅在库为空时可用)。"""
    d = db()
    if d.execute("SELECT COUNT(*) FROM athletes").fetchone()[0]:
        return jsonify(error='当前已有数据。如需演示,请先在设置里“清空全部数据”'), 400
    S = settings()
    random.seed(7)
    colors = [('红队', '#dc2626'), ('蓝队', '#2563eb'), ('黄队', '#ca8a04'), ('绿队', '#16a34a')]
    tids = [d.execute("INSERT INTO teams(name,color,sort) VALUES(?,?,?)", (n, c, i)).lastrowid for i, (n, c) in enumerate(colors)]
    sur, giv = '王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗', '伟芳娜敏静丽强磊军洋勇艳杰涛明超秀霞平刚桂英华'
    for i in range(80):
        g_ = 'M' if i % 2 == 0 else 'F'
        d.execute("INSERT INTO athletes(name,gender,team_id) VALUES(?,?,?)",
                  (random.choice(sur) + random.choice(giv) + (random.choice(giv) if random.random() < .6 else ''), g_, tids[i % 4]))
    d.commit()
    for i, r in enumerate(d.execute("SELECT id FROM athletes ORDER BY id").fetchall()):
        d.execute("UPDATE athletes SET bib=? WHERE id=?", (str(i + 1).zfill(3), r['id']))
    day = datetime.now().strftime('%Y-%m-%d')
    t = datetime.strptime(day + ' 08:30', '%Y-%m-%d %H:%M')
    eids = []
    for g_ in ('M', 'F'):
        for name, kind, dur in PRESETS:
            cur = d.execute("INSERT INTO events(%s) VALUES(%s)" % (EV_COLS, ','.join('?' * 15)),
                            (('男子' if g_ == 'M' else '女子') + name, kind, g_, None, t.strftime('%Y-%m-%d %H:%M'), dur,
                             '田径场' if kind != 'field' else '沙坑/投掷区', 8, 'scheduled', 1, None,
                             {'100米': 12.5, '跳远': 5.2}.get(name) if g_ == 'M' and name in ('100米', '跳远') else None,
                             '2019 届 张明' if g_ == 'M' and name in ('100米', '跳远') else None, None, None))
            eids.append((cur.lastrowid, kind, g_, name))
            t += timedelta(minutes=dur if kind != 'field' else 15)
    d.commit()
    ath = {g_: [r['id'] for r in d.execute("SELECT id FROM athletes WHERE gender=?", (g_,))] for g_ in ('M', 'F')}
    for eid, kind, g_, name in eids:
        if kind == 'relay':
            for ti in tids:
                d.execute("INSERT INTO entries(event_id,team_id,label,members) VALUES(?,?,?,?)", (eid, ti, 'A队', ''))
        else:
            for aid in random.sample(ath[g_], 14 if kind == 'track' else 10):
                try:
                    d.execute("INSERT INTO entries(event_id,athlete_id) VALUES(?,?)", (eid, aid))
                except sqlite3.IntegrityError:
                    pass
    d.commit()
    log('载入演示数据')
    d.commit()
    return jsonify(ok=True)


# ----------------------------------------------------------------- 启动
def main():
    init_db()
    with app.app_context():
        if '--reset-password' in sys.argv or not get_raw('pw_admin'):
            pw = '%06d' % random.SystemRandom().randrange(1000000)
            put_setting('pw_admin', hash_pw(pw))
            db().commit()
            with open(os.path.join(DATA, '管理员密码.txt'), 'w', encoding='utf-8') as f:
                f.write('管理员密码: %s\n(登录后请在“设置”页修改,并删除此文件)\n' % pw)
            print('\n  >>> 管理员密码: %s   (已保存到 data/管理员密码.txt)\n' % pw)
            if '--reset-password' in sys.argv:
                return
    port = 8000
    if '--port' in sys.argv:
        port = int(sys.argv[sys.argv.index('--port') + 1])
    print('  校运会成绩系统已启动')
    print('  本机访问:   http://127.0.0.1:%d' % port)
    for ip in lan_ips():
        print('  局域网访问: http://%s:%d   (同一 Wi-Fi/网段的手机、平板、电脑均可打开)' % (ip, port))
    print('  按 Ctrl+C 停止\n')
    try:
        from waitress import serve
        serve(app, host='0.0.0.0', port=port, threads=8)
    except ImportError:
        app.run(host='0.0.0.0', port=port, threaded=True)


init_db()
if __name__ == '__main__':
    main()
