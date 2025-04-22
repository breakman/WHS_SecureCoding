import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from markupsafe import escape
from flask_socketio import SocketIO, send
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta, datetime
import pyotp  # 2단계 인증용
from cryptography.fernet import Fernet  # 암호화용

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 실제 운영에서는 더 강력한 키를 사용해야 합니다
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['ENCRYPTION_KEY'] = Fernet.generate_key()  # 암호화 키 생성
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)

# XSS 방지: HTML 이스케이프 처리
def safe_render_template(template, **kwargs):
    # 모든 문자열 값을 이스케이프 처리
    escaped_kwargs = {}
    for key, value in kwargs.items():
        if isinstance(value, str):
            escaped_kwargs[key] = escape(value)
        elif isinstance(value, list):
            escaped_kwargs[key] = [escape(item) if isinstance(item, str) else item for item in value]
        elif isinstance(value, dict):
            escaped_kwargs[key] = {k: escape(v) if isinstance(v, str) else v for k, v in value.items()}
        else:
            escaped_kwargs[key] = value
    return render_template(template, **escaped_kwargs)

# SQL 인젝션 방지: 입력값 검증 및 정제
def sanitize_input(input_str):
    # SQL 특수문자 제거
    return re.sub(r'[;\'"\\]', '', input_str)

# 관리자 권한 레벨 정의
ADMIN_ROLES = {
    'USER_MANAGER': 1,      # 사용자 관리 권한
    'REPORT_MANAGER': 2,    # 신고 처리 권한
    'LOG_VIEWER': 3,        # 로그 조회 권한
    'SUPER_ADMIN': 4        # 모든 권한
}

# 관리자 권한 확인 데코레이터
def admin_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or not session.get('is_admin'):
                flash('관리자 권한이 필요합니다.')
                return redirect(url_for('login'))
            
            # 관리자 권한 레벨 확인
            db = get_db()
            cursor = db.cursor()
            cursor.execute("""
                SELECT role_level FROM admin_roles 
                WHERE user_id = ?
            """, (session['user_id'],))
            role = cursor.fetchone()
            
            if not role or role['role_level'] < required_role:
                flash('해당 기능에 대한 접근 권한이 없습니다.')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 데이터베이스 연결 관리
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

# 트랜잭션 실행 함수
def execute_transaction(db, operations):
    """
    여러 데이터베이스 작업을 하나의 트랜잭션으로 실행합니다.
    
    Args:
        db: 데이터베이스 연결 객체
        operations: 실행할 작업 목록. 각 작업은 'query'와 'params' 키를 가진 딕셔너리여야 합니다.
    """
    cursor = db.cursor()
    try:
        for operation in operations:
            cursor.execute(operation['query'], operation['params'])
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        cursor.close()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        try:
            # 기존 테이블 삭제
            cursor.execute("DROP TABLE IF EXISTS admin_roles")
            cursor.execute("DROP TABLE IF EXISTS admin_log")
            cursor.execute("DROP TABLE IF EXISTS chat_message")
            cursor.execute("DROP TABLE IF EXISTS money_transfer")
            cursor.execute("DROP TABLE IF EXISTS report")
            cursor.execute("DROP TABLE IF EXISTS product")
            cursor.execute("DROP TABLE IF EXISTS transaction_log")
            cursor.execute("DROP TABLE IF EXISTS user")
            
            # 사용자 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    bio TEXT,
                    is_admin INTEGER DEFAULT 0,
                    balance INTEGER DEFAULT 0,
                    two_factor_secret TEXT,
                    status TEXT DEFAULT 'active',
                    blocked_at TIMESTAMP,
                    blocked_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (blocked_by) REFERENCES user(id)
                )
            """)
            
            # 상품 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS product (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    price INTEGER NOT NULL,
                    seller_id TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (seller_id) REFERENCES user(id)
                )
            """)
            
            # 신고 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS report (
                    id TEXT PRIMARY KEY,
                    reporter_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP,
                    resolved_by TEXT,
                    FOREIGN KEY (reporter_id) REFERENCES user(id),
                    FOREIGN KEY (target_id) REFERENCES user(id),
                    FOREIGN KEY (resolved_by) REFERENCES user(id)
                )
            """)
            
            # 송금 테이블 생성 (시스템 송금 허용)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS money_transfer (
                    id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    receiver_id TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    description TEXT,
                    encrypted_data BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (receiver_id) REFERENCES user(id)
                )
            """)
            
            # 송금 트리거 생성 - 시스템 송금 또는 유효한 사용자만 허용
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS check_sender_id
                BEFORE INSERT ON money_transfer
                BEGIN
                    SELECT CASE
                        WHEN NEW.sender_id != 'system' AND NOT EXISTS (
                            SELECT 1 FROM user WHERE id = NEW.sender_id
                        )
                        THEN RAISE(ABORT, 'Invalid sender_id')
                    END;
                END;
            """)
            
            # 거래 로그 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transaction_log (
                    id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    receiver_id TEXT,
                    amount INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # 채팅 메시지 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS chat_message (
                    id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    receiver_id TEXT,
                    message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES user(id),
                    FOREIGN KEY (receiver_id) REFERENCES user(id)
                )
            """)
            
            # 관리자 로그 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admin_log (
                    id TEXT PRIMARY KEY,
                    admin_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_id TEXT,
                    details TEXT,
                    status TEXT DEFAULT 'success',
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (admin_id) REFERENCES user(id),
                    FOREIGN KEY (target_id) REFERENCES user(id)
                )
            """)
            
            # 관리자 권한 테이블 생성
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admin_roles (
                    user_id TEXT PRIMARY KEY,
                    role_level INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES user(id)
                )
            """)
            
            # 기본 관리자 계정 생성
            admin_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO user (id, username, password, is_admin, balance) VALUES (?, ?, ?, ?, ?)",
                (admin_id, 'admin', generate_password_hash('asdf1234'), 1, 0)
            )
            # 기본 관리자에게 SUPER_ADMIN 권한 부여
            cursor.execute(
                "INSERT INTO admin_roles (user_id, role_level) VALUES (?, ?)",
                (admin_id, ADMIN_ROLES['SUPER_ADMIN'])
            )
            
            # 테스트 사용자 계정 생성
            test_user_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO user (id, username, password, is_admin, balance) VALUES (?, ?, ?, ?, ?)",
                (test_user_id, 'test_user', generate_password_hash('test1234'), 0, 1000)
            )
            
            # 테스트 신고 데이터 추가
            test_report_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO report (id, reporter_id, target_id, target_type, reason, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (test_report_id, admin_id, test_user_id, 'user', '테스트 신고', 'pending'))
            
            db.commit()
            print("데이터베이스가 성공적으로 초기화되었습니다.")
            print("관리자 계정 - 아이디: admin, 비밀번호: asdf1234")
            
        except Exception as e:
            db.rollback()
            app.logger.error(f'데이터베이스 초기화 오류: {str(e)}')
            raise e
        finally:
            cursor.close()

# 입력값 검증 강화
def validate_input(data, rules):
    # 정규식 패턴 검증
    for field, rule in rules.items():
        if field not in data:
            return False, f"{field} 필드가 필요합니다."
        if not re.match(rule, str(data[field])):
            return False, f"{field} 필드가 올바른 형식이 아닙니다."
    
    # 길이 제한 검증
    length_rules = {
        'username': (4, 20),
        'password': (8, 100),
        'title': (1, 100),
        'description': (1, 1000),
        'message': (1, 500),
        'bio': (0, 500)
    }
    
    for field, (min_len, max_len) in length_rules.items():
        if field in data and not (min_len <= len(str(data[field])) <= max_len):
            return False, f"{field} 필드의 길이는 {min_len}에서 {max_len} 사이여야 합니다."
    
    return True, ""

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return safe_render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 입력값 검증
        rules = {
            'username': r'^[a-zA-Z0-9_]{4,20}$',
            'password': r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'
        }
        is_valid, message = validate_input(request.form, rules)
        if not is_valid:
            flash(message)
            return redirect(url_for('register'))
        
        db = get_db()
        cursor = db.cursor()
        
        try:
            # 사용자명 중복 체크
            cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
            if cursor.fetchone() is not None:
                flash('이미 존재하는 사용자명입니다.')
                return redirect(url_for('register'))
            
            # 새 사용자 생성
            user_id = str(uuid.uuid4())
            hashed_password = generate_password_hash(password)
            
            cursor.execute(
                "INSERT INTO user (id, username, password, is_admin, balance) VALUES (?, ?, ?, ?, ?)",
                (user_id, username, hashed_password, 0, 0)
            )
            db.commit()
            
            app.logger.info(f'새 사용자 등록 성공: {username}')
            flash('회원가입이 완료되었습니다. 로그인 해주세요.')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.rollback()
            app.logger.error(f'회원가입 오류: {str(e)}')
            flash('회원가입 중 오류가 발생했습니다. 다시 시도해주세요.')
            return redirect(url_for('register'))
        finally:
            cursor.close()
    
    return safe_render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['is_admin'] = bool(user['is_admin'])
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return safe_render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    
    # 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # 최근 거래 내역 조회 (최근 10건)
    cursor.execute("""
        SELECT 
            mt.*,
            CASE 
                WHEN mt.sender_id = ? THEN u_receiver.username
                ELSE u_sender.username
            END as other_username,
            (
                SELECT balance 
                FROM (
                    SELECT 
                        id,
                        sender_id,
                        receiver_id,
                        amount,
                        created_at,
                        SUM(CASE 
                            WHEN receiver_id = ? THEN amount 
                            WHEN sender_id = ? THEN -amount 
                            ELSE 0 
                        END) OVER (ORDER BY created_at) as balance
                    FROM money_transfer
                    WHERE sender_id = ? OR receiver_id = ?
                ) t
                WHERE t.id = mt.id
            ) as balance
        FROM money_transfer mt
        LEFT JOIN user u_sender ON mt.sender_id = u_sender.id
        LEFT JOIN user u_receiver ON mt.receiver_id = u_receiver.id
        WHERE mt.sender_id = ? OR mt.receiver_id = ?
        ORDER BY mt.created_at DESC
        LIMIT 10
    """, (session['user_id'], session['user_id'], session['user_id'], 
          session['user_id'], session['user_id'], session['user_id'], session['user_id']))
    
    transactions = cursor.fetchall()
    
    return safe_render_template('profile.html', user=current_user, transactions=transactions)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # 입력값 정제
        title = sanitize_input(request.form['title'])
        description = sanitize_input(request.form['description'])
        price = sanitize_input(request.form['price'])
        
        # 가격이 숫자인지 검증
        if not price.isdigit():
            flash('가격은 숫자만 입력 가능합니다.')
            return redirect(url_for('new_product'))
        
        price = int(price)
        # 최소 가격 검증
        if price < 1000:
            flash('최소 가격은 1,000원 이상이어야 합니다.')
            return redirect(url_for('new_product'))
            
        db = get_db()
        cursor = db.cursor()
        
        try:
            # 상품 등록과 인센티브 지급을 트랜잭션으로 처리
            product_id = str(uuid.uuid4())
            incentive = int(price * 0.1)  # 10% 인센티브
            
            operations = [
                {
                    'query': """
                        INSERT INTO product (id, title, description, price, seller_id) 
                        VALUES (?, ?, ?, ?, ?)
                    """,
                    'params': (product_id, title, description, price, session['user_id'])
                },
                {
                    'query': """
                        UPDATE user 
                        SET balance = balance + ? 
                        WHERE id = ?
                    """,
                    'params': (incentive, session['user_id'])
                },
                {
                    'query': """
                        INSERT INTO money_transfer (
                            id, sender_id, receiver_id, amount, description
                        ) VALUES (?, ?, ?, ?, ?)
                    """,
                    'params': (
                        str(uuid.uuid4()),
                        'system',  # 시스템에서 지급하는 인센티브
                        session['user_id'],
                        incentive,
                        f'상품 등록 인센티브 (상품: {title})'
                    )
                }
            ]
            
            execute_transaction(db, operations)
            flash(f'상품이 등록되었습니다. {incentive:,}원의 인센티브가 지급되었습니다.')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.rollback()
            app.logger.error(f'상품 등록 오류: {str(e)}')
            flash('상품 등록 중 오류가 발생했습니다.')
            return redirect(url_for('new_product'))
        finally:
            cursor.close()
            
    return safe_render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        target_type = request.form['target_type']
        reason = request.form['reason']
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            target_id = None
            
            if target_type == 'user':
                target_username = request.form['target_username']
                if not target_username:
                    flash('사용자 이름을 입력해주세요.', 'danger')
                    return redirect(url_for('report'))
                
                # 사용자 조회
                cursor.execute('SELECT id FROM user WHERE username = ?', (target_username,))
                user = cursor.fetchone()
                if not user:
                    flash('존재하지 않는 사용자입니다.', 'danger')
                    return redirect(url_for('report'))
                
                target_id = user['id']
                
            elif target_type == 'product':
                product_title = request.form['target_product']
                if not product_title:
                    flash('상품 제목을 입력해주세요.', 'danger')
                    return redirect(url_for('report'))
                
                # 상품 조회
                cursor.execute('SELECT id, seller_id FROM product WHERE title = ?', (product_title,))
                product = cursor.fetchone()
                if not product:
                    flash('존재하지 않는 상품입니다.', 'danger')
                    return redirect(url_for('report'))
                
                target_id = product['seller_id']  # 상품의 판매자 ID를 대상으로 설정
            
            # 신고 등록
            report_id = str(uuid.uuid4())[:8]  # UUID의 앞 8자리만 사용
            cursor.execute('''
                INSERT INTO report (id, reporter_id, target_id, reason, status, target_type)
                VALUES (?, ?, ?, ?, 'pending', ?)
            ''', (report_id, session['user_id'], target_id, reason, target_type))
            
            conn.commit()
            flash('신고가 접수되었습니다.', 'success')
            
            # 대시보드로 리다이렉트
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            conn.rollback()
            flash('신고 접수 중 오류가 발생했습니다.', 'danger')
            print(f"Error submitting report: {str(e)}")
            return redirect(url_for('report'))
        finally:
            conn.close()
    
    return render_template('report.html')

# 거래 내역 암호화/복호화
def encrypt_transaction_data(data):
    key = app.config['ENCRYPTION_KEY']
    f = Fernet(key)
    return f.encrypt(str(data).encode())

def decrypt_transaction_data(encrypted_data):
    key = app.config['ENCRYPTION_KEY']
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

# 2단계 인증 설정
def setup_2fa(user_id):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(f"user_{user_id}", issuer_name="Marketplace")
    return secret, provisioning_uri

# 2단계 인증 검증
def verify_2fa(user_id, code):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT two_factor_secret FROM user WHERE id = ?", (user_id,))
    secret = cursor.fetchone()['two_factor_secret']
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

# 거래 금액 검증
def validate_transaction_amount(amount, user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 일일 거래 한도 확인
    cursor.execute("""
        SELECT SUM(amount) as daily_total 
        FROM money_transfer 
        WHERE sender_id = ? 
        AND date(created_at) = date('now')
    """, (user_id,))
    daily_total = cursor.fetchone()['daily_total'] or 0
    
    # 계정 잔액 확인
    cursor.execute("SELECT balance FROM user WHERE id = ?", (user_id,))
    balance = cursor.fetchone()['balance']
    
    # 거래 한도 설정
    DAILY_LIMIT = 1000000  # 일일 거래 한도
    SINGLE_LIMIT = 500000  # 단일 거래 한도
    
    if amount > SINGLE_LIMIT:
        return False, "단일 거래 한도를 초과했습니다."
    if daily_total + amount > DAILY_LIMIT:
        return False, "일일 거래 한도를 초과했습니다."
    if amount > balance:
        return False, "잔액이 부족합니다."
    
    return True, ""

# 송금 기능
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자 정보 조회
    cursor.execute("""
        SELECT id, username, balance, two_factor_secret 
        FROM user 
        WHERE id = ?
    """, (session['user_id'],))
    user = cursor.fetchone()
    
    if not user:
        flash('사용자 정보를 찾을 수 없습니다.')
        session.clear()
        return redirect(url_for('login'))
    
    # 2FA가 설정되지 않은 경우 자동 설정
    if not user['two_factor_secret']:
        try:
            secret, uri = setup_2fa(user['id'])
            cursor.execute("UPDATE user SET two_factor_secret = ? WHERE id = ?", (secret, user['id']))
            db.commit()
            flash('2단계 인증이 설정되었습니다. 인증 코드: ' + pyotp.TOTP(secret).now())
            return redirect(url_for('transfer'))
        except Exception as e:
            db.rollback()
            app.logger.error(f'2FA 설정 오류: {str(e)}')
            flash('2단계 인증 설정 중 오류가 발생했습니다.')
            return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        receiver_username = request.form['receiver']
        amount = int(request.form['amount'])
        description = request.form.get('description', '')
        verification_code = request.form.get('verification_code')
        
        # 입력값 검증
        rules = {
            'receiver': r'^[a-zA-Z0-9_]{4,20}$',
            'amount': r'^\d+$',
            'description': r'^.{0,100}$',
            'verification_code': r'^\d{6}$'
        }
        is_valid, message = validate_input(request.form, rules)
        if not is_valid:
            flash(message)
            return redirect(url_for('transfer'))
        
        # 2단계 인증 검증
        if not verify_2fa(user['id'], verification_code):
            flash('인증 코드가 올바르지 않습니다.')
            return redirect(url_for('transfer'))
        
        # 거래 금액 검증
        is_valid_amount, amount_message = validate_transaction_amount(amount, user['id'])
        if not is_valid_amount:
            flash(amount_message)
            return redirect(url_for('transfer'))
        
        try:
            # 수신자 정보 조회
            cursor.execute("SELECT id FROM user WHERE username = ?", (receiver_username,))
            receiver = cursor.fetchone()
            if not receiver:
                flash('수신자를 찾을 수 없습니다.')
                return redirect(url_for('transfer'))
            
            # 거래 내역 암호화
            transaction_data = {
                'sender_id': user['id'],
                'receiver_id': receiver['id'],
                'amount': amount,
                'description': description
            }
            encrypted_data = encrypt_transaction_data(transaction_data)
            
            # 트랜잭션으로 송금 처리
            operations = [
                {
                    'query': "INSERT INTO money_transfer (id, sender_id, receiver_id, amount, description, encrypted_data) VALUES (?, ?, ?, ?, ?, ?)",
                    'params': (str(uuid.uuid4()), user['id'], receiver['id'], amount, description, encrypted_data)
                },
                {
                    'query': "UPDATE user SET balance = balance - ? WHERE id = ?",
                    'params': (amount, user['id'])
                },
                {
                    'query': "UPDATE user SET balance = balance + ? WHERE id = ?",
                    'params': (amount, receiver['id'])
                }
            ]
            execute_transaction(db, operations)
            
            # 거래 로그 기록
            log_transaction(user['id'], receiver['id'], amount, 'success')
            
            flash('송금이 완료되었습니다.')
            return redirect(url_for('dashboard'))
        except Exception as e:
            # 거래 실패 로그 기록
            log_transaction(user['id'], receiver['id'] if 'receiver' in locals() else None, amount, 'failed', str(e))
            flash('송금 중 오류가 발생했습니다.')
            return redirect(url_for('transfer'))
    
    # GET 요청 처리
    receiver = request.args.get('receiver', '')
    amount = request.args.get('amount', '')
    
    # 수신자가 비어있거나 금액이 유효하지 않은 경우
    if not receiver or not amount or not amount.isdigit():
        flash('올바르지 않은 요청입니다.')
        return redirect(url_for('dashboard'))
        
    return safe_render_template('transfer.html', receiver=receiver, amount=amount, user=user)

# 거래 로그 기록
def log_transaction(sender_id, receiver_id, amount, status, error_message=None):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO transaction_log (
            id, sender_id, receiver_id, amount, status, error_message, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    """, (str(uuid.uuid4()), sender_id, receiver_id, amount, status, error_message))
    db.commit()

# 상품 검색
@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    query = request.args.get('q', '')
    if not query:
        return redirect(url_for('dashboard'))
    
    # 입력값 정제 및 길이 제한
    query = sanitize_input(query)
    if len(query) > 100:  # 검색어 길이 제한
        flash('검색어가 너무 깁니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    # SQL 인젝션 방지: 파라미터 바인딩과 와일드카드 처리
    search_pattern = f'%{query}%'
    cursor.execute("""
        SELECT 
            p.id,
            p.title,
            p.description,
            p.price,
            p.status,
            p.created_at,
            u.username as seller_username,
            u.id as seller_id
        FROM product p
        JOIN user u ON p.seller_id = u.id
        WHERE (p.title LIKE ? OR p.description LIKE ?)
        AND p.status = 'active'
        AND (
            -- 판매 중인 상품만 검색
            p.status = 'active'
            OR
            -- 자신이 판매한 상품은 모든 상태에서 검색 가능
            p.seller_id = ?
        )
        ORDER BY p.created_at DESC
        LIMIT 50  -- 결과 수 제한
    """, (search_pattern, search_pattern, session['user_id']))
    
    results = cursor.fetchall()
    
    # 민감 정보 필터링
    filtered_results = []
    for result in results:
        filtered_result = dict(result)
        # 불필요한 정보 제거
        del filtered_result['seller_id']
        filtered_results.append(filtered_result)
    
    return safe_render_template('search_results.html', results=filtered_results, query=query)

# 관리자 활동 로깅 함수 개선
def log_admin_action(action, target_id=None, details=None, status='success'):
    if 'user_id' not in session or not session.get('is_admin'):
        return
    
    db = get_db()
    cursor = db.cursor()
    log_id = str(uuid.uuid4())
    
    # IP 주소 및 사용자 에이전트 정보 추가
    ip_address = request.remote_addr
    user_agent = request.user_agent.string
    
    cursor.execute("""
        INSERT INTO admin_log (
            id, admin_id, action, target_id, details, 
            status, ip_address, user_agent, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    """, (log_id, session['user_id'], action, target_id, details, 
          status, ip_address, user_agent))
    db.commit()

# 관리자 기능: 사용자 관리
@app.route('/admin/users')
@admin_required(ADMIN_ROLES['USER_MANAGER'])
def admin_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT u.*, ar.role_level 
        FROM user u
        LEFT JOIN admin_roles ar ON u.id = ar.user_id
        ORDER BY u.created_at DESC
    """)
    users = cursor.fetchall()
    
    log_admin_action('view_users')
    return render_template('admin_users.html', users=users)

# 관리자 기능: 신고 처리
@app.route('/admin/reports')
@admin_required(ADMIN_ROLES['REPORT_MANAGER'])
def admin_reports():
    if not session.get('is_admin'):
        flash('관리자만 접근할 수 있습니다.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # 신고 목록 조회 (신고자, 대상자 정보 포함)
        cursor.execute('''
            SELECT 
                r.id as report_id,
                r.reporter_id,
                r.target_id,
                r.target_type,
                r.reason,
                r.status,
                r.created_at,
                r.resolved_at,
                r.resolved_by,
                u1.username as reporter_name,
                u2.username as target_name,
                u3.username as resolved_by_name
            FROM report r
            JOIN user u1 ON r.reporter_id = u1.id
            JOIN user u2 ON r.target_id = u2.id
            LEFT JOIN user u3 ON r.resolved_by = u3.id
            ORDER BY r.created_at DESC
        ''')
        
        reports = cursor.fetchall()
        
        # 디버깅을 위한 로그 추가
        app.logger.debug(f"신고 목록: {reports}")
        for report in reports:
            app.logger.debug(f"신고 ID: {report['report_id']}, 상태: {report['status']}")
        
        if not reports:
            app.logger.warning("신고 목록이 비어있습니다.")
            flash('현재 처리할 신고가 없습니다.', 'info')
        
    except Exception as e:
        app.logger.error(f"신고 목록 조회 중 오류 발생: {str(e)}")
        flash('신고 목록을 불러오는 중 오류가 발생했습니다.', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        conn.close()
    
    return render_template('admin_reports.html', reports=reports)

# 관리자 기능: 신고 처리 액션
@app.route('/admin/report/<string:report_id>/<string:action>')
@admin_required(ADMIN_ROLES['REPORT_MANAGER'])
def handle_report(report_id, action):
    if not session.get('is_admin'):
        flash('관리자만 접근할 수 있습니다.', 'danger')
        return redirect(url_for('dashboard'))
    
    if action not in ['approve', 'reject']:
        flash('잘못된 요청입니다.', 'danger')
        return redirect(url_for('admin_reports'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # 신고 정보 조회
        cursor.execute('SELECT * FROM report WHERE id = ?', (report_id,))
        report = cursor.fetchone()
        
        if not report:
            flash('존재하지 않는 신고입니다.', 'danger')
            return redirect(url_for('admin_reports'))
        
        if report['status'] != 'pending':
            flash('이미 처리된 신고입니다.', 'warning')
            return redirect(url_for('admin_reports'))
        
        # 신고 처리
        if action == 'approve':
            # 대상 사용자 차단
            cursor.execute('''
                UPDATE user 
                SET status = 'blocked',
                    blocked_at = CURRENT_TIMESTAMP,
                    blocked_by = ?
                WHERE id = ?
            ''', (session['user_id'], report['target_id']))
            
            # 신고 상태 변경
            cursor.execute('''
                UPDATE report 
                SET status = 'approved',
                    resolved_at = CURRENT_TIMESTAMP,
                    resolved_by = ?
                WHERE id = ?
            ''', (session['user_id'], report_id))
            
            # 관리자 로그 기록
            cursor.execute('''
                INSERT INTO admin_log (admin_id, action, target_id, details, ip_address)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                session['user_id'],
                'report_approve',
                report['target_id'],
                f'신고 ID: {report_id}, 사유: {report["reason"]}',
                request.remote_addr
            ))
            
            flash('신고가 승인되었습니다.', 'success')
        else:
            # 신고 거부
            cursor.execute('''
                UPDATE report 
                SET status = 'rejected',
                    resolved_at = CURRENT_TIMESTAMP,
                    resolved_by = ?
                WHERE id = ?
            ''', (session['user_id'], report_id))
            
            # 관리자 로그 기록
            cursor.execute('''
                INSERT INTO admin_log (admin_id, action, target_id, details, ip_address)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                session['user_id'],
                'report_reject',
                report['target_id'],
                f'신고 ID: {report_id}, 사유: {report["reason"]}',
                request.remote_addr
            ))
            
            flash('신고가 거부되었습니다.', 'info')
        
        conn.commit()
        
    except Exception as e:
        conn.rollback()
        flash('신고 처리 중 오류가 발생했습니다.', 'danger')
        print(f"Error handling report: {str(e)}")
        
    finally:
        conn.close()
    
    return redirect(url_for('admin_reports'))

# 관리자 기능: 로그 조회
@app.route('/admin/logs')
@admin_required(ADMIN_ROLES['LOG_VIEWER'])
def admin_logs():
    db = get_db()
    cursor = db.cursor()
    
    # 로그 조회 기간 설정 (기본 30일)
    days = request.args.get('days', 30, type=int)
    if days < 1 or days > 90:  # 최대 90일로 제한
        days = 30
    
    cursor.execute("""
        SELECT l.*, u.username as admin_name 
        FROM admin_log l
        JOIN user u ON l.admin_id = u.id
        WHERE l.created_at >= datetime('now', ? || ' days')
        ORDER BY l.created_at DESC
        LIMIT 1000
    """, (f'-{days}',))
    
    logs = cursor.fetchall()
    
    log_admin_action('view_logs', details=f'조회 기간: {days}일')
    return render_template('admin_logs.html', logs=logs, days=days)

# 실시간 채팅
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    if 'user_id' not in session:
        return False
    return True

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('message')
def handle_message(data):
    print('Received message:', data)  # 디버깅용 로그
    if 'user_id' not in session:
        return
    
    # 메시지 검증
    message = data.get('message', '').strip()
    if not message or len(message) > 500:
        return
    
    # 사용자 이름 조회
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('SELECT username FROM user WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        if not user:
            return
        
        # 메시지 저장
        message_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO chat_message (id, sender_id, message, created_at)
            VALUES (?, ?, ?, datetime('now'))
        ''', (message_id, session['user_id'], message))
        db.commit()
        
        # 메시지 브로드캐스트
        socketio.emit('message', {
            'message': message,
            'username': user['username'],
            'timestamp': datetime.now().strftime('%H:%M:%S')
        })
        
    except Exception as e:
        db.rollback()
        print(f"Error handling message: {str(e)}")
    finally:
        cursor.close()

# 관리자 기능: 사용자 상세 정보 조회
@app.route('/admin/user/<user_id>')
@admin_required(ADMIN_ROLES['USER_MANAGER'])
def admin_user_detail(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 조회
    cursor.execute("""
        SELECT u.*, ar.role_level 
        FROM user u
        LEFT JOIN admin_roles ar ON u.id = ar.user_id
        WHERE u.id = ?
    """, (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('admin_users'))
    
    # 사용자의 거래 내역 조회
    cursor.execute("""
        SELECT mt.*, 
            u1.username as sender_name,
            u2.username as receiver_name
        FROM money_transfer mt
        LEFT JOIN user u1 ON mt.sender_id = u1.id
        LEFT JOIN user u2 ON mt.receiver_id = u2.id
        WHERE mt.sender_id = ? OR mt.receiver_id = ?
        ORDER BY mt.created_at DESC
        LIMIT 50
    """, (user_id, user_id))
    transactions = cursor.fetchall()
    
    # 사용자의 상품 목록 조회
    cursor.execute("""
        SELECT * FROM product
        WHERE seller_id = ?
        ORDER BY created_at DESC
    """, (user_id,))
    products = cursor.fetchall()
    
    # 사용자에 대한 신고 내역 조회
    cursor.execute("""
        SELECT r.*, u.username as reporter_name
        FROM report r
        JOIN user u ON r.reporter_id = u.id
        WHERE r.target_id = ?
        ORDER BY r.created_at DESC
    """, (user_id,))
    reports = cursor.fetchall()
    
    log_admin_action('view_user_detail', user_id)
    return render_template('admin_user_detail.html', 
                         user=user, 
                         transactions=transactions,
                         products=products,
                         reports=reports)

# 관리자 기능: 사용자 차단
@app.route('/admin/user/<user_id>/block')
@admin_required(ADMIN_ROLES['USER_MANAGER'])
def admin_block_user(user_id):
    db = get_db()
    cursor = db.cursor()
    
    try:
        # 사용자 상태를 '차단됨'으로 변경
        cursor.execute("""
            UPDATE user 
            SET status = 'blocked',
                blocked_at = datetime('now'),
                blocked_by = ?
            WHERE id = ?
        """, (session['user_id'], user_id))
        
        # 사용자의 모든 상품을 비활성화
        cursor.execute("""
            UPDATE product
            SET status = 'inactive'
            WHERE seller_id = ?
        """, (user_id,))
        
        db.commit()
        log_admin_action('block_user', user_id, '사용자 차단 처리')
        flash('사용자가 차단되었습니다.')
        
    except Exception as e:
        db.rollback()
        log_admin_action('block_user', user_id, str(e), 'failed')
        flash('사용자 차단 중 오류가 발생했습니다.')
    
    return redirect(url_for('admin_users'))

# 관리자 기능: 관리자 권한 부여
@app.route('/admin/add-admin', methods=['GET', 'POST'])
@admin_required(ADMIN_ROLES['SUPER_ADMIN'])
def admin_add_admin():
    if request.method == 'GET':
        return render_template('admin_add_admin.html')
    
    # POST 요청 처리
    if not request.form.get('username') or not request.form.get('role_level'):
        flash('필수 정보가 누락되었습니다.')
        return redirect(url_for('admin_users'))
    
    username = request.form['username']
    role_level = int(request.form['role_level'])
    
    # 권한 레벨 검증
    if role_level not in ADMIN_ROLES.values():
        flash('올바르지 않은 권한 레벨입니다.')
        return redirect(url_for('admin_users'))
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # 사용자 존재 여부 확인
        cursor.execute("SELECT id FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            flash('존재하지 않는 사용자입니다.')
            return redirect(url_for('admin_users'))
        
        # 이미 관리자인지 확인
        cursor.execute("SELECT role_level FROM admin_roles WHERE user_id = ?", (user['id'],))
        existing_role = cursor.fetchone()
        if existing_role:
            flash('이미 관리자 권한을 가진 사용자입니다.')
            return redirect(url_for('admin_users'))
        
        # 관리자 권한 부여
        operations = [
            {
                'query': "UPDATE user SET is_admin = 1 WHERE id = ?",
                'params': (user['id'],)
            },
            {
                'query': "INSERT INTO admin_roles (user_id, role_level) VALUES (?, ?)",
                'params': (user['id'], role_level)
            }
        ]
        execute_transaction(db, operations)
        
        log_admin_action('add_admin', user['id'], f'권한 레벨: {role_level}')
        flash('관리자 권한이 부여되었습니다.')
        
    except Exception as e:
        db.rollback()
        log_admin_action('add_admin', user['id'] if 'user' in locals() else None, 
                        str(e), 'failed')
        flash('관리자 권한 부여 중 오류가 발생했습니다.')
    
    return redirect(url_for('admin_users'))

@app.route('/user/<user_id>')
def view_user_detail(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 조회
    cursor.execute("""
        SELECT id, username, status, is_admin, balance, created_at
        FROM user
        WHERE id = ?
    """, (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 사용자의 상품 목록 조회
    cursor.execute("""
        SELECT id, title, price, status, created_at
        FROM product
        WHERE seller_id = ?
        ORDER BY created_at DESC
    """, (user_id,))
    products = cursor.fetchall()
    
    return render_template('view_user_detail.html', user=user, products=products)


if __name__ == '__main__':
    # init_db()  # 데이터베이스 초기화
    # socketio.run(app, debug=True)  # 앱 실행
    init_db()
    
    # 외부 접근 허용 설정
    app.run(host='0.0.0.0', port=5000, debug=True)