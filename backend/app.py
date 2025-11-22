import os
import sqlite3
import base64
import json
import time
import shutil
from datetime import datetime
from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO
import hashlib 

from flask import Flask, request, render_template, redirect, url_for, send_file, session, g, flash
from werkzeug.utils import secure_filename
import requests 
from functools import wraps

# --- 您的百度云密钥配置配置 ---
# 请替换为您的实际密钥
API_KEY = "BAIDU_API_KEY"
SECRET_KEY = "BAIDU_SECRET_KEY"
# ----------------------

# 鉴权接口 URL
TOKEN_URL = "https://aip.baidubce.com/oauth/2.0/token"
OCR_URL = "https://aip.baidubce.com/rest/2.0/ocr/v1/vat_invoice"

# 缓存 Access Token
ACCESS_TOKEN = None
TOKEN_EXPIRATION_TIME = 0
ADMIN_USERNAME = 'admin' 
# 示例密码 admin123 的 SHA256 散列值
ADMIN_PASSWORD_HASH = hashlib.sha256('admin123'.encode()).hexdigest() 

app = Flask(__name__)
UPLOAD_FOLDER = 'data/invoices'
ATTACHMENT_FOLDER = 'data/attachments' 
DB_PATH = 'data/invoices.db'

# --- 启用 Session 的必需配置 (重要!) ---
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/' 
# ----------------------------------------

# 确保文件夹存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ATTACHMENT_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


# --- 数据库操作 ---

def get_db_connection():
    """获取数据库连接并创建表"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    # 1. 发票表 (invoices)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reimburser_name TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_path TEXT,
            new_file_name TEXT,
            invoice_code TEXT,
            invoice_num TEXT,
            invoice_date TEXT,
            total_amount REAL,
            tax_amount REAL,
            status TEXT NOT NULL,
            remarks TEXT,
            seller_name TEXT, 
            seller_tax_id TEXT,
            item_name TEXT,
            total_figuers REAL,
            user_comment TEXT,
            reimbursement_status TEXT DEFAULT '未报销',
            pay_to_seller INTEGER DEFAULT 0  -- 0=对个人报销，1=对公转账给销售方
        )
    ''')
    
    # 2. 用户表 (users)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            reimburser_name TEXT UNIQUE NOT NULL 
        )
    ''')

    # 3. 附件表 (attachments)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL,
            reimburser_name TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            new_file_name TEXT NOT NULL,
            FOREIGN KEY (invoice_id) REFERENCES invoices (id) ON DELETE CASCADE
        )
    ''')
    
    # 兼容旧版本字段（如果数据库已存在，添加新字段）
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(invoices)")
    invoice_columns = [col[1] for col in cursor.fetchall()]
    
    if 'reimbursement_status' not in invoice_columns:
        try:
            conn.execute("ALTER TABLE invoices ADD COLUMN reimbursement_status TEXT DEFAULT '未报销'")
        except sqlite3.OperationalError:
            pass
            
    if 'pay_to_seller' not in invoice_columns:
        try:
            conn.execute("ALTER TABLE invoices ADD COLUMN pay_to_seller INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
    if 'user_comment' not in invoice_columns:
        try:
            conn.execute("ALTER TABLE invoices ADD COLUMN user_comment TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass

    conn.commit()
    return conn

def hash_password(password):
    """使用 SHA-256 散列密码"""
    return hashlib.sha256(password.encode()).hexdigest()

# --- 认证辅助函数和装饰器 ---

@app.before_request
def load_logged_in_user():
    """在每次请求前加载用户信息"""
    user_id = session.get('user_id')
    user_type = session.get('user_type')
    
    g.user = None
    g.is_admin = False
    
    if user_id is not None:
        conn = get_db_connection()
        if user_type == 'admin':
            g.user = {'id': 0, 'username': ADMIN_USERNAME, 'reimburser_name': '管理员'}
            g.is_admin = True
        else:
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            g.user = user if user else None
        conn.close()

def login_required(f):
    """要求登录的装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login', next=request.url)) 
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """要求管理员权限的装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.is_admin:
            return "无权访问管理后台。", 403
        return f(*args, **kwargs)
    return decorated_function

# --- 百度 OCR 鉴权与识别函数 ---

def get_access_token():
    """获取百度云 Access Token"""
    global ACCESS_TOKEN, TOKEN_EXPIRATION_TIME
    # 如果 token 存在且在 1 分钟内未过期，则使用缓存
    if ACCESS_TOKEN and TOKEN_EXPIRATION_TIME > time.time() + 60:
        return ACCESS_TOKEN

    try:
        params = {
            "grant_type": "client_credentials",
            "client_id": API_KEY,
            "client_secret": SECRET_KEY
        }
        
        response = requests.post(TOKEN_URL, params=params)
        response.raise_for_status() 
        
        result = response.json()
        
        if 'access_token' in result:
            ACCESS_TOKEN = result['access_token']
            expires_in = result.get('expires_in', 2592000) 
            TOKEN_EXPIRATION_TIME = time.time() + expires_in
            return ACCESS_TOKEN
        else:
            print(f"获取 Token 失败: {result}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"请求百度云 Token 失败: {e}")
        return None

def recognize_invoice(file_content: bytes, reimburser_name: str, file_extension: str, is_pdf: bool):
    """调用百度云增值税发票识别接口并提取信息"""
    token = get_access_token()
    if not token:
        return None, None
        
    try:
        img_base64 = base64.b64encode(file_content).decode('utf-8')

        if is_pdf:
            params = {"pdf_file": img_base64}
        else:
            params = {"image": img_base64}
            
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        request_url = f"{OCR_URL}?access_token={token}"
        
        response = requests.post(request_url, data=params, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        
        if 'error_code' in result:
            print(f"OCR 识别 API 返回错误: {result.get('error_msg')}")
            return None, None

        words_result = result.get('words_result', {})
        
        # --- 基础信息提取 ---
        invoice_code = words_result.get('InvoiceCode', 'N/A')
        invoice_num = words_result.get('InvoiceNum', 'N/A')
        invoice_date_str = words_result.get('InvoiceDate', '').replace('年', '-').replace('月', '-').replace('日', '')
        try:
            if len(invoice_date_str) == 8 and invoice_date_str.isdigit():
                 invoice_date_str = f"{invoice_date_str[:4]}-{invoice_date_str[4:6]}-{invoice_date_str[6:]}"
        except Exception:
            invoice_date_str = 'N/A'
            
        # --- 健壮地处理金额转换 ---
        
        # 1. 价税合计 (TotalAmountInFiguers)
        total_figuers_str = words_result.get('AmountInFiguers', '0.00') 
        try:
            cleaned_figuers = total_figuers_str.replace(',', '').strip()
            total_figuers = float(cleaned_figuers)
        except ValueError:
            total_figuers = 0.00

        # 2. 税额 (TotalTax)
        total_tax_str = words_result.get('TotalTax')
        try:
            cleaned_tax = str(total_tax_str or '0').replace(',', '').strip()
            total_tax = float(cleaned_tax)
        except ValueError:
            total_tax = 0.00
            
        # 3. 金额 (TotalAmount - 不含税)
        total_amount_str = words_result.get('TotalAmount')
        try:
            cleaned_amount = str(total_amount_str or '0').replace(',', '').strip()
            total_amount = float(cleaned_amount)
        except ValueError:
            total_amount = 0.00
            
        # --- 健壮处理结束 ---
        
        seller_name = words_result.get('SellerName', 'N/A')
        seller_tax_id = words_result.get('SellerRegisterNum', 'N/A')

        item_name = 'N/A'
        commodity_list = words_result.get('CommodityName')
        if commodity_list and isinstance(commodity_list, list) and commodity_list[0].get('word'):
            item_name = commodity_list[0]['word'].replace('/', '_').replace(' ', '')
        
        trip_info = words_result.get('Remarks', '')
        rename_suffix = ""

        # 特殊处理：检查是否有通行费信息
        if words_result.get('CommodityPlateNum'):
            plate_num = words_result['CommodityPlateNum'][0]['word'] if words_result.get('CommodityPlateNum') and words_result['CommodityPlateNum'] else 'N/A'
            rename_suffix = f"_{plate_num}"
            
            start_date = words_result['CommodityStartDate'][0]['word'] if words_result.get('CommodityStartDate') and words_result['CommodityStartDate'] else 'N/A'
            end_date = words_result['CommodityEndDate'][0]['word'] if words_result.get('CommodityEndDate') and words_result['CommodityEndDate'] else 'N/A'
            trip_info = f"车牌号:{plate_num}, 通行起:{start_date}, 通行止:{end_date}"
            
        # --- 智能重命名 ---
        date_for_rename = invoice_date_str.replace('-', '')
        amount_for_rename = f"{total_figuers:.2f}"
        
        seller_name_safe = seller_name.replace('/', '_').replace(' ', '')
        item_name_safe = item_name.replace('/', '_').replace(' ', '')

        # 核心修复：使用传入的 file_extension 作为后缀名
        # 格式：[日期]_[报销人]_[项目名称]_[销售方名称]_[价税合计(含税)]_[可选后缀].[原始后缀名]
        new_name = f"{date_for_rename}_{reimburser_name}_{item_name_safe}_{seller_name_safe}_{amount_for_rename}{rename_suffix}{file_extension}"
        
        return {
            'invoice_code': invoice_code,
            'invoice_num': invoice_num,
            'invoice_date': invoice_date_str,
            'total_amount': total_amount, 
            'tax_amount': total_tax,
            'remarks': trip_info,
            'seller_name': seller_name,
            'seller_tax_id': seller_tax_id,
            'item_name': item_name,
            'total_figuers': total_figuers
        }, new_name

    except requests.exceptions.RequestException as e:
        print(f"调用 OCR 识别接口失败 (网络或鉴权错误): {e}")
        return None, None
    except Exception as e:
        print(f"处理 OCR 结果时发生错误: {e}")
        return None, None


# --- 路由及视图函数 ---

# 1. 注册 
@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册路由"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        reimburser_name = request.form.get('reimburser_name')
        error = None
        
        if not username or not password or not reimburser_name:
            error = '所有字段都是必填项。'
        
        if error is None:
            conn = get_db_connection()
            try:
                if username == ADMIN_USERNAME:
                    error = '该用户名已被系统保留。'
                else:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, reimburser_name) VALUES (?, ?, ?)",
                        (username, hash_password(password), reimburser_name)
                    )
                    conn.commit()
            except sqlite3.IntegrityError:
                error = f"用户名 {username} 或姓名 {reimburser_name} 已被使用。"
            finally:
                conn.close()
                
            if error is None:
                return redirect(url_for('login'))
        
        return render_template('register.html', error=error)
    return render_template('register.html', error=None)

# 2. 登录 
@app.route('/', methods=['GET', 'POST'])
def login():
    """用户和管理员登录路由"""
    if g.user:
        if g.is_admin:
            return redirect(url_for('admin_view'))
        else:
            return redirect(url_for('my_invoices'))
            
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_hash_input = hash_password(password)
        error = None
        
        if username == ADMIN_USERNAME:
            if password_hash_input == ADMIN_PASSWORD_HASH:
                session.clear()
                session['user_id'] = 0
                session['user_type'] = 'admin'
                return redirect(url_for('admin_view'))
            else:
                error = '管理员密码错误'
        
        else:
            conn = get_db_connection()
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()
            conn.close()

            if user is None:
                error = '用户名不存在。'
            elif user['password_hash'] != password_hash_input:
                error = '密码错误。'

            if error is None:
                session.clear()
                session['user_id'] = user['id']
                session['user_type'] = 'user'
                next_url = request.args.get('next') or url_for('my_invoices')
                return redirect(next_url)
        
        return render_template('login.html', error=error)
        
    return render_template('login.html', error=None)

# 3. 退出 
@app.route('/logout')
def logout():
    """退出登录路由"""
    session.clear()
    return redirect(url_for('login'))

# 4. 用户修改密码 
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """用户修改密码路由"""
    error = None
    success = None
    
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not old_password or not new_password or not confirm_password:
            error = '所有密码字段都是必填项。'
        elif new_password != confirm_password:
            error = '新密码和确认密码不一致。'
        elif len(new_password) < 6:
            error = '新密码长度至少为6位。'
            
        if error is None:
            conn = get_db_connection()
            if g.is_admin:
                error = '管理员账号请联系系统维护人员重置密码。'
            else:
                user = conn.execute(
                    'SELECT * FROM users WHERE id = ?', (g.user['id'],)
                ).fetchone()
                
                if user['password_hash'] == hash_password(old_password):
                    # 更新密码
                    new_hash = hash_password(new_password)
                    conn.execute(
                        'UPDATE users SET password_hash = ? WHERE id = ?',
                        (new_hash, g.user['id'])
                    )
                    conn.commit()
                    success = '密码修改成功，请重新登录！'
                    conn.close()
                    # 强制用户重新登录
                    session.clear()
                    return redirect(url_for('login'))
                else:
                    error = '原密码输入错误。'
            conn.close()
            
    return render_template('change_password.html', error=error, success=success)

# 5. 个人用户页面 (发票上传和列表)
@app.route('/my_invoices', methods=['GET', 'POST'])
@login_required
def my_invoices():
    """用户发票管理页面，支持上传、识别和列表展示"""
    reimburser_name = g.user['reimburser_name']
    conn = get_db_connection()
    
    if request.method == 'POST':
        # --- 处理文件上传 (发票) ---
        files = request.files.getlist('invoices')
        if not files:
            conn.close()
            return "缺少发票文件", 400

        for file in files:
            if file.filename == '':
                continue
            
            original_filename = secure_filename(file.filename)
            # 核心修复点：获取原始文件后缀名
            file_base, file_extension = os.path.splitext(original_filename)
            file_extension = file_extension.lower()
            is_pdf_file = file_extension == '.pdf'
            
            temp_path = os.path.join('/tmp', original_filename)
            
            try:
                # 尝试保存到临时目录
                file.save(temp_path)
            except Exception as e:
                print(f"保存文件到 /tmp 失败: {e}")
                continue

            ocr_data = None
            new_file_name = None
            try:
                with open(temp_path, 'rb') as f:
                    file_content = f.read()
                
                # 核心修复点：传递 file_extension 给 recognize_invoice
                ocr_data, new_file_name = recognize_invoice(
                    file_content, reimburser_name, file_extension, is_pdf_file
                )
            except Exception as e:
                print(f"读取或识别文件 {original_filename} 失败: {e}")

            if ocr_data:
                # 识别成功
                final_path = os.path.join(UPLOAD_FOLDER, new_file_name)
                try:
                    # 移动文件到最终目录
                    shutil.move(temp_path, final_path)
                except Exception as e:
                    print(f"移动/重命名文件失败: {e}. 保持原名路径: {temp_path}")
                    final_path = temp_path # 如果移动失败，使用临时路径作为最后的保险
                
                conn.execute('''
                    INSERT INTO invoices 
                    (reimburser_name, original_filename, file_path, new_file_name, 
                     invoice_code, invoice_num, invoice_date, total_amount, tax_amount, status, remarks,
                     seller_name, seller_tax_id, item_name, total_figuers, reimbursement_status, pay_to_seller)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (reimburser_name, original_filename, final_path, new_file_name,
                      ocr_data['invoice_code'], ocr_data['invoice_num'], 
                      ocr_data['invoice_date'], ocr_data['total_amount'], 
                      ocr_data['tax_amount'], '已识别', ocr_data['remarks'],
                      ocr_data['seller_name'], ocr_data['seller_tax_id'], 
                      ocr_data['item_name'], ocr_data['total_figuers'], '未报销', 0))
            else:
                 # 识别失败
                 conn.execute('''
                    INSERT INTO invoices 
                    (reimburser_name, original_filename, file_path, status, reimbursement_status, 
                     new_file_name, invoice_code, invoice_num, invoice_date, total_amount, tax_amount, 
                     remarks, seller_name, seller_tax_id, item_name, total_figuers, pay_to_seller)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (reimburser_name, original_filename, None, '识别失败', '未报销', 
                      None, 'N/A', 'N/A', 'N/A', 0.0, 0.0, 
                      '识别失败，文件非标准发票', 'N/A', 'N/A', 'N/A', 0.0, 0))
                 
            conn.commit()
            
            # 无论成功失败，都清理 /tmp 文件
            if os.path.exists(temp_path):
                 try:
                     os.remove(temp_path)
                 except Exception as e:
                     print(f"Error deleting temp file {temp_path}: {e}")

        conn.close()
        return redirect(url_for('my_invoices'))
    
    # GET: 显示列表
    invoices_raw = conn.execute(
        'SELECT * FROM invoices WHERE reimburser_name = ? ORDER BY id DESC', 
        (reimburser_name,)
    ).fetchall()
    
    # 附加附件信息
    invoices = []
    for row in invoices_raw:
        invoice = dict(row)
        attachments = conn.execute(
            'SELECT * FROM attachments WHERE invoice_id = ?', 
            (invoice['id'],)
        ).fetchall()
        invoice['attachments'] = [dict(att) for att in attachments]
        invoices.append(invoice)
        
    conn.close()
    return render_template('my_invoices.html', invoices=invoices, reimburser_name=reimburser_name)
    
# 6. 个人用户路由 - 添加附件
@app.route('/add_attachment/<int:invoice_id>', methods=['POST'])
@login_required
def add_attachment(invoice_id):
    """批量上传附件并为每个文件正确编号"""
    reimburser_name = g.user['reimburser_name']
    files = request.files.getlist('attachments')
    
    if not files:
        return "缺少附件文件", 400

    conn = get_db_connection()
    
    invoice = conn.execute(
        'SELECT new_file_name FROM invoices WHERE id = ? AND reimburser_name = ?', 
        (invoice_id, reimburser_name)
    ).fetchone()

    if not invoice:
        conn.close()
        return "发票未找到或您无权操作。", 404
        
    invoice_new_name = invoice['new_file_name'] or f"invoice_{invoice_id}"
    # 使用发票的重命名文件作为附件的基础名称
    base_name = os.path.splitext(invoice_new_name)[0] 

    uploaded_count = 0
    
    current_attachments_count = conn.execute(
        'SELECT COUNT(*) FROM attachments WHERE invoice_id = ?', (invoice_id,)
    ).fetchone()[0]
    
    attachment_counter = current_attachments_count + 1
    
    for file in files: 
        if file.filename == '':
            continue
            
        original_filename = secure_filename(file.filename)
        # 使用 os.path.splitext 获取原始文件扩展名
        _, file_extension = os.path.splitext(original_filename)
        
        # 构造新文件名，确保包含扩展名
        new_attachment_name = f"{base_name}-附件{attachment_counter}{file_extension.lower()}"
        attachment_counter += 1 
        
        final_path = os.path.join(ATTACHMENT_FOLDER, new_attachment_name)
        
        try:
            file.save(final_path)
            
            conn.execute('''
                INSERT INTO attachments 
                (invoice_id, reimburser_name, original_filename, file_path, new_file_name)
                VALUES (?, ?, ?, ?, ?)
            ''', (invoice_id, reimburser_name, original_filename, final_path, new_attachment_name))
            conn.commit()
            uploaded_count += 1
            
        except Exception as e:
            print(f"保存附件 {original_filename} 失败: {e}")
            if os.path.exists(final_path):
                os.remove(final_path)

    conn.close()
    if uploaded_count > 0:
        return redirect(url_for('my_invoices'))
    else:
        return "没有附件上传成功。", 400

# 7. 个人用户路由 - 切换对公状态
@app.route('/my_invoices/mark_pay_to_seller/<int:invoice_id>', methods=['POST'])
@login_required
def mark_pay_to_seller(invoice_id):
    """用户切换发票的对公转账状态"""
    reimburser_name = g.user['reimburser_name']
    state = request.form.get('state') 
    is_pay_to_seller = 1 if state == '1' else 0

    conn = get_db_connection()
    
    invoice = conn.execute(
        'SELECT * FROM invoices WHERE id = ? AND reimburser_name = ?', 
        (invoice_id, reimburser_name)
    ).fetchone()

    if invoice:
        conn.execute(
            'UPDATE invoices SET pay_to_seller = ? WHERE id = ?', 
            (is_pay_to_seller, invoice_id)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('my_invoices'))
    
    conn.close()
    return "发票未找到或您无权操作。", 404

# 8. 个人用户路由 - 批量操作
@app.route('/my_invoices/batch_action', methods=['POST'])
@login_required
def my_invoices_batch_action():
    """用户批量操作发票 (对公/对个人, 删除)"""
    reimburser_name = g.user['reimburser_name']
    action = request.form.get('action')
    invoice_ids = request.form.getlist('invoice_ids')
    
    if not invoice_ids:
        return redirect(url_for('my_invoices'))
        
    conn = get_db_connection()
    cursor = conn.cursor() 
    
    try:
        if action == 'mark_pay_to_seller':
            cursor.executemany(
                'UPDATE invoices SET pay_to_seller = 1 WHERE id = ? AND reimburser_name = ?', 
                [(id, reimburser_name) for id in invoice_ids]
            )
            
        elif action == 'unmark_pay_to_seller':
            cursor.executemany(
                'UPDATE invoices SET pay_to_seller = 0 WHERE id = ? AND reimburser_name = ?', 
                [(id, reimburser_name) for id in invoice_ids]
            )

        elif action == 'delete_batch':
            # 1. 查询待删除的发票记录
            invoices_to_delete = cursor.execute(
                'SELECT id, file_path FROM invoices WHERE id IN ({}) AND reimburser_name = ?'.format(
                    ','.join(['?'] * len(invoice_ids))), 
                invoice_ids + [reimburser_name]
            ).fetchall()
            
            # 2. 删除文件和附件
            for invoice in invoices_to_delete:
                invoice_id = invoice['id']
                file_path = invoice['file_path']
                
                if file_path and os.path.exists(file_path): 
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Error deleting invoice file {file_path}: {e}")
                
                attachments_to_delete = cursor.execute(
                    'SELECT file_path FROM attachments WHERE invoice_id = ?', (invoice_id,)
                ).fetchall()
                
                for attachment in attachments_to_delete:
                    att_path = attachment['file_path']
                    if att_path and os.path.exists(att_path):
                        try:
                            os.remove(att_path)
                        except Exception as e:
                            print(f"Error deleting attachment file {att_path}: {e}")

            # 3. 删除数据库记录
            cursor.executemany(
                'DELETE FROM invoices WHERE id = ? AND reimburser_name = ?', 
                [(id, reimburser_name) for id in invoice_ids]
            )

        conn.commit()
        
    except Exception as e:
        print(f"用户批量操作失败: {e}")
        conn.rollback()
        return f"操作失败: 数据库或文件操作异常", 500 
        
    finally:
        conn.close()
        
    return redirect(url_for('my_invoices'))

# 9. 个人用户路由 - 删除发票
@app.route('/my_invoices/delete/<int:invoice_id>', methods=['POST'])
@login_required
def delete_invoice(invoice_id):
    """用户删除单个发票及附件"""
    reimburser_name = g.user['reimburser_name']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    invoice = cursor.execute(
        'SELECT id, file_path FROM invoices WHERE id = ? AND reimburser_name = ?', 
        (invoice_id, reimburser_name)
    ).fetchone()
    
    if invoice:
        file_path = invoice['file_path']
        
        if file_path and os.path.exists(file_path): 
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error deleting invoice file {file_path}: {e}")
        
        attachments_to_delete = cursor.execute(
            'SELECT file_path FROM attachments WHERE invoice_id = ?', (invoice_id,)
        ).fetchall()
        
        for attachment in attachments_to_delete:
            att_path = attachment['file_path']
            if att_path and os.path.exists(att_path):
                try:
                    os.remove(att_path)
                except Exception as e:
                    print(f"Error deleting attachment file {att_path}: {e}")
        
        cursor.execute('DELETE FROM invoices WHERE id = ?', (invoice_id,))
        
        conn.commit()
        conn.close()
        return redirect(url_for('my_invoices'))
    
    conn.close()
    return "发票未找到或您无权删除此发票。", 404

# 10. 个人用户路由 - 删除附件
@app.route('/my_invoices/delete_attachment/<int:attachment_id>', methods=['POST'])
@login_required
def delete_attachment(attachment_id):
    """用户删除单个附件"""
    reimburser_name = g.user['reimburser_name']
    conn = get_db_connection()
    
    attachment = conn.execute(
        'SELECT * FROM attachments WHERE id = ? AND reimburser_name = ?', 
        (attachment_id, reimburser_name)
    ).fetchone()
    
    if attachment:
        file_path = attachment['file_path']
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error deleting attachment file {file_path}: {e}")
        
        conn.execute('DELETE FROM attachments WHERE id = ?', (attachment_id,))
        conn.commit()
        conn.close()
        return redirect(url_for('my_invoices'))
    
    conn.close()
    return "附件未找到或您无权删除此附件。", 404

# 11. 管理后台总览页面 
@app.route('/admin', methods=['GET'])
@admin_required
def admin_view():
    """管理员发票列表页面"""
    conn = get_db_connection()
    invoices_raw = conn.execute('SELECT * FROM invoices ORDER BY id DESC').fetchall()
    
    invoices = []
    for row in invoices_raw:
        invoice = dict(row)
        attachments = conn.execute(
            'SELECT * FROM attachments WHERE invoice_id = ?', 
            (invoice['id'],)
        ).fetchall()
        invoice['attachments'] = [dict(att) for att in attachments]
        invoices.append(invoice)
        
    conn.close()
    
    status_options = ['未报销', '已报销']
    return render_template('admin.html', invoices=invoices, status_options=status_options)

# 12. 管理员用户管理页面 
@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_user_management():
    """管理员用户管理页面"""
    conn = get_db_connection()
    error = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_user':
            username = request.form.get('username')
            reimburser_name = request.form.get('reimburser_name')
            initial_password = f"{username}123" 
            
            if not username or not reimburser_name:
                error = "用户名和报销人姓名不能为空。"
            elif username == ADMIN_USERNAME:
                 error = '该用户名已被系统保留。'
            else:
                try:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, reimburser_name) VALUES (?, ?, ?)",
                        (username, hash_password(initial_password), reimburser_name)
                    )
                    conn.commit()
                    return redirect(url_for('admin_user_management'))
                except sqlite3.IntegrityError:
                    error = f"用户名 {username} 或姓名 {reimburser_name} 已被使用。"
                except Exception as e:
                    error = f"添加用户失败: {e}"
                    
        elif action == 'delete_batch':
            user_ids = request.form.getlist('user_ids')
            if not user_ids:
                error = '请选择要删除的用户。'
            else:
                try:
                    conn.executemany(
                        'DELETE FROM users WHERE id = ?', 
                        [(uid,) for uid in user_ids]
                    )
                    conn.commit()
                    return redirect(url_for('admin_user_management'))
                except Exception as e:
                    error = f"批量删除用户失败: {e}"

    # GET 请求和 POST 失败后加载用户列表
    users_raw = conn.execute('SELECT id, username, reimburser_name FROM users ORDER BY id ASC').fetchall()
    users = [dict(row) for row in users_raw]
    conn.close()
    
    return render_template('user_management.html', users=users, error=error)

# 13. 管理员重置单个用户密码 
@app.route('/admin/users/reset_password/<int:user_id>', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    """管理员重置单个用户的密码为 [username]123"""
    if user_id == 0:
        return "管理员账号无法通过此功能重置。", 403
        
    conn = get_db_connection()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user:
        username = user['username']
        new_password = f"{username}123" 
        new_hash = hash_password(new_password)
        
        try:
            conn.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (new_hash, user_id)
            )
            conn.commit()
            conn.close()
            return redirect(url_for('admin_user_management')) 
        except Exception as e:
            conn.close()
            return f"密码重置失败: {e}", 500
    
    conn.close()
    return "用户未找到。", 404

# 14. 管理员切换单个发票对公状态
@app.route('/admin/mark_pay_to_seller/<int:invoice_id>', methods=['POST'])
@admin_required
def admin_mark_pay_to_seller(invoice_id):
    """管理员切换单个发票的对公转账状态"""
    state = request.form.get('state') 
    is_pay_to_seller = 1 if state == '1' else 0

    conn = get_db_connection()
    
    invoice = conn.execute(
        'SELECT id FROM invoices WHERE id = ?', (invoice_id,)
    ).fetchone()

    if invoice:
        conn.execute(
            'UPDATE invoices SET pay_to_seller = ? WHERE id = ?', 
            (is_pay_to_seller, invoice_id)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('admin_view'))
    
    conn.close()
    return "发票未找到。", 404

# 15. 管理员删除附件
@app.route('/admin/delete_attachment/<int:attachment_id>', methods=['POST'])
@admin_required
def admin_delete_attachment(attachment_id):
    """管理员删除单个附件"""
    conn = get_db_connection()
    
    attachment = conn.execute(
        'SELECT * FROM attachments WHERE id = ?', (attachment_id,)
    ).fetchone()
    
    if attachment:
        file_path = attachment['file_path']
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error deleting attachment file {file_path}: {e}")
        
        conn.execute('DELETE FROM attachments WHERE id = ?', (attachment_id,))
        conn.commit()
        conn.close()
        return redirect(url_for('admin_view'))
    
    conn.close()
    return "附件未找到。", 404
    
# 16. 管理员新增附件
@app.route('/admin/add_attachment/<int:invoice_id>', methods=['POST'])
@admin_required
def admin_add_attachment(invoice_id):
    """管理员为发票添加附件"""
    files = request.files.getlist('attachments')
    
    if not files:
        return "缺少附件文件", 400

    conn = get_db_connection()
    
    invoice = conn.execute(
        'SELECT new_file_name, reimburser_name FROM invoices WHERE id = ?', 
        (invoice_id,)
    ).fetchone()

    if not invoice:
        conn.close()
        return "发票未找到。", 404
        
    reimburser_name = invoice['reimburser_name']
    invoice_new_name = invoice['new_file_name'] or f"invoice_{invoice_id}"
    # 使用发票的重命名文件作为附件的基础名称
    base_name = os.path.splitext(invoice_new_name)[0]

    uploaded_count = 0
    
    current_attachments_count = conn.execute(
        'SELECT COUNT(*) FROM attachments WHERE invoice_id = ?', (invoice_id,)
    ).fetchone()[0]
    
    attachment_counter = current_attachments_count + 1
    
    for file in files: 
        if file.filename == '':
            continue
            
        original_filename = secure_filename(file.filename)
        # 使用 os.path.splitext 获取原始文件扩展名
        _, file_extension = os.path.splitext(original_filename)
        
        # 构造新文件名，确保包含扩展名
        new_attachment_name = f"{base_name}-附件{attachment_counter}{file_extension.lower()}"
        attachment_counter += 1 
        
        final_path = os.path.join(ATTACHMENT_FOLDER, new_attachment_name)
        
        try:
            file.save(final_path)
            
            conn.execute('''
                INSERT INTO attachments 
                (invoice_id, reimburser_name, original_filename, file_path, new_file_name)
                VALUES (?, ?, ?, ?, ?)
            ''', (invoice_id, reimburser_name, original_filename, final_path, new_attachment_name))
            conn.commit()
            uploaded_count += 1
            
        except Exception as e:
            print(f"保存附件 {original_filename} 失败: {e}")
            if os.path.exists(final_path):
                os.remove(final_path)

    conn.close()
    if uploaded_count > 0:
        return redirect(url_for('admin_view'))
    else:
        return "没有附件上传成功。", 400

# 17. 管理员批量操作
@app.route('/admin/batch_action', methods=['POST'])
@admin_required
def admin_batch_action():
    """管理员批量操作发票 (报销状态, 对公状态, 删除)"""
    action = request.form.get('action')
    invoice_ids = request.form.getlist('invoice_ids')
    
    if not invoice_ids:
        return redirect(url_for('admin_view'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if action in ['set_reimbursed', 'set_pending']:
            new_status = '已报销' if action == 'set_reimbursed' else '未报销'
            cursor.executemany(
                'UPDATE invoices SET reimbursement_status = ? WHERE id = ?', 
                [(new_status, id) for id in invoice_ids]
            )
        elif action == 'mark_pay_to_seller': 
            cursor.executemany(
                'UPDATE invoices SET pay_to_seller = 1 WHERE id = ?', 
                [(id,) for id in invoice_ids]
            )
        elif action == 'unmark_pay_to_seller': 
            cursor.executemany(
                'UPDATE invoices SET pay_to_seller = 0 WHERE id = ?', 
                [(id,) for id in invoice_ids]
            )
        elif action == 'delete_batch':
            # 1. 查询待删除的发票记录
            invoices_to_delete = cursor.execute(
                'SELECT id, file_path FROM invoices WHERE id IN ({})'.format(
                    ','.join(['?'] * len(invoice_ids))), 
                invoice_ids
            ).fetchall()
            
            # 2. 删除文件和附件
            for invoice in invoices_to_delete:
                invoice_id = invoice['id']
                file_path = invoice['file_path']
                
                if file_path and os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Error deleting invoice file {file_path}: {e}")
                        
                attachments_to_delete = cursor.execute(
                    'SELECT file_path FROM attachments WHERE invoice_id = ?', (invoice_id,)
                ).fetchall()
                
                for attachment in attachments_to_delete:
                    att_path = attachment['file_path']
                    if att_path and os.path.exists(att_path):
                        try:
                            os.remove(att_path)
                        except Exception as e:
                            print(f"Error deleting attachment file {att_path}: {e}")
            
            # 3. 删除数据库记录
            cursor.executemany(
                'DELETE FROM invoices WHERE id = ?', 
                [(id,) for id in invoice_ids]
            )
            
        conn.commit()
    except Exception as e:
        print(f"管理员批量操作失败: {e}")
        conn.rollback()
        return f"操作失败: 数据库或文件操作异常", 500
    finally:
        conn.close()
    return redirect(url_for('admin_view'))
    
# 18. 管理员删除发票 (单个)
@app.route('/admin/delete/<int:invoice_id>', methods=['POST'])
@admin_required
def admin_delete_invoice(invoice_id):
    """管理员删除单个发票及附件"""
    conn = get_db_connection()
    cursor = conn.cursor()
    invoice = cursor.execute('SELECT id, file_path FROM invoices WHERE id = ?', (invoice_id,)).fetchone()
    if invoice:
        file_path = invoice['file_path']
        
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error deleting invoice file {file_path}: {e}")
                
        attachments_to_delete = cursor.execute(
            'SELECT file_path FROM attachments WHERE invoice_id = ?', (invoice_id,)
        ).fetchall()
        
        for attachment in attachments_to_delete:
            att_path = attachment['file_path']
            if att_path and os.path.exists(att_path):
                try:
                    os.remove(att_path)
                except Exception as e:
                    print(f"Error deleting attachment file {att_path}: {e}")
        
        cursor.execute('DELETE FROM invoices WHERE id = ?', (invoice_id,))
        
        conn.commit()
        conn.close()
        return redirect(url_for('admin_view'))
    conn.close()
    return "发票未找到。", 404

# 19. 管理员导出 (修复发票号码格式)
@app.route('/admin/export', methods=['GET'])
@admin_required
def admin_export():
    """打包导出所有发票和包含 '报销状态' 的 CSV"""
    conn = get_db_connection()
    invoices_raw = conn.execute('SELECT * FROM invoices').fetchall()
    attachments_raw = conn.execute('SELECT * FROM attachments').fetchall()
    conn.close()
    
    invoices = [dict(row) for row in invoices_raw]
    attachments = [dict(row) for row in attachments_raw]
    
    csv_output = BytesIO()
    csv_output.write(b'\xEF\xBB\xBF') # UTF-8 BOM
    
    # --- CSV 表头 ---
    new_header = "ID,报销人,对公转账,发票号码,开票日期,项目名称,销售方名称,销售方统一信用代码,价税合计(含税),报销状态,上传人批注,发票备注,重命名文件\n"
    csv_output.write(new_header.encode('utf-8'))
    
    # CSV Data
    for inv in invoices: 
        inv_id = inv.get('id')
        pay_to_seller = inv.get('pay_to_seller', 0)
        
        if pay_to_seller == 1:
            reimburser_name = inv.get('seller_name') or 'N/A' 
            pay_to_seller_label = '是'
        else:
            reimburser_name = inv.get('reimburser_name') or 'N/A' 
            pay_to_seller_label = '否'
        
        reimbursement_status = inv.get('reimbursement_status') or '未报销' 
        
        # 核心修复点：将发票号码用双引号包裹，使其被识别为文本
        invoice_num_raw = inv.get('invoice_num') or 'N/A'
        invoice_num = f'"\t{invoice_num_raw}"'
        
        invoice_date = inv.get('invoice_date') or 'N/A'
        item_name = inv.get('item_name') or 'N/A'
        seller_name = inv.get('seller_name') or 'N/A'
        seller_tax_id_raw = inv.get('seller_tax_id') or 'N/A'
        seller_tax_id = f'"\t{seller_tax_id_raw}"'
        total_figuers = inv.get('total_figuers') or 0.00
        new_file_name = inv.get('new_file_name') or 'N/A'
        remarks_data = inv.get('remarks') or ''
        remarks_safe = json.dumps(remarks_data, ensure_ascii=False).strip('"')
        user_comment_safe = inv.get('user_comment', '').replace('\n', ' ').replace('\r', '')
        if inv_id is None:
            continue
            
        row = f"{inv_id},{reimburser_name},{pay_to_seller_label},{invoice_num},{invoice_date},{item_name},{seller_name},{seller_tax_id},{total_figuers:.2f},{reimbursement_status},{user_comment_safe},{remarks_safe},{new_file_name}\n"
        csv_output.write(row.encode('utf-8'))
    
    # 文件打包
    zip_buffer = BytesIO()
    with ZipFile(zip_buffer, 'w', ZIP_DEFLATED) as zf: 
        zf.writestr('发票识别表格数据.csv', csv_output.getvalue())
        
        # 1. 写入发票文件 
        for inv in invoices:
            if inv.get('status') == '已识别': 
                file_path = inv.get('file_path')
                target_name = inv.get('new_file_name')
                
                if file_path and os.path.exists(file_path) and target_name: 
                    zf.write(file_path, os.path.join('发票文件', target_name))
        
        # 2. 写入附件文件 
        for att in attachments:
            file_path = att.get('file_path')
            target_name = att.get('new_file_name')
            
            if file_path and os.path.exists(file_path) and target_name: 
                zf.write(file_path, os.path.join('附件文件', target_name))
                

    zip_buffer.seek(0)
    
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'发票管理系统导出_{datetime.now().strftime("%Y%m%d%H%M%S")}.zip'
    )

# 20. 更新批注（新路由）
@app.route('/update_comment/<int:invoice_id>', methods=['POST'])
@login_required
def update_comment(invoice_id):
    """用户或管理员更新发票批注"""
    # 获取表单提交的批注内容，并去除首尾空格
    new_comment = request.form.get('user_comment', '').strip()
    
    conn = get_db_connection()
    
    # 所有人都可以更新这个字段，但需要验证发票是否存在且权限正确
    
    if g.is_admin:
        # 管理员可以更新所有发票
        invoice = conn.execute('SELECT id FROM invoices WHERE id = ?', (invoice_id,)).fetchone()
    else:
        # 普通用户只能更新自己的发票
        reimburser_name = g.user['reimburser_name']
        invoice = conn.execute(
            'SELECT id FROM invoices WHERE id = ? AND reimburser_name = ?', 
            (invoice_id, reimburser_name)
        ).fetchone()

    if invoice:
        try:
            # 执行更新操作
            conn.execute(
                'UPDATE invoices SET user_comment = ? WHERE id = ?', 
                (new_comment, invoice_id)
            )
            conn.commit()
            conn.close()
            # 成功后重定向到发票所在行的位置
            anchor = f'#invoice-row-{invoice_id}'
            if g.is_admin:
                return redirect(url_for('admin_view') + anchor)
            else:
                return redirect(url_for('my_invoices') + anchor)
        except Exception as e:
            print(f"Error updating user_comment: {e}")
            conn.close()
            return "数据库更新失败。", 500
    
    conn.close()
    return "发票未找到或您无权修改该发票。", 404

if __name__ == '__main__':
    get_access_token() 
    get_db_connection().close() 
    app.run(host='0.0.0.0', port=5000, debug=True)
