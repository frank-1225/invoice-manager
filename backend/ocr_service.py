# backend/ocr_service.py

import requests
import base64
import json
import time

# --- 您的百度云密钥 ---
API_KEY = ""
SECRET_KEY = ""
# ----------------------

# 鉴权接口 URL
TOKEN_URL = "https://aip.baidubce.com/oauth/2.0/token"
# 增值税发票识别接口 URL
OCR_URL = "https://aip.baidubce.com/rest/2.0/ocr/v1/vat_invoice"

# 缓存 Access Token
ACCESS_TOKEN = None
TOKEN_EXPIRATION_TIME = 0

def get_access_token():
    """
    获取百度云 Access Token 并缓存，避免频繁请求。
    """
    global ACCESS_TOKEN, TOKEN_EXPIRATION_TIME
    
    # 检查缓存是否有效 (提前1分钟过期)
    if ACCESS_TOKEN and TOKEN_EXPIRATION_TIME > time.time() + 60:
        return ACCESS_TOKEN

    try:
        params = {
            "grant_type": "client_credentials",
            "client_id": API_KEY,
            "client_secret": SECRET_KEY
        }
        
        response = requests.post(TOKEN_URL, params=params)
        response.raise_for_status() # 检查 HTTP 错误
        
        result = response.json()
        
        if 'access_token' in result:
            ACCESS_TOKEN = result['access_token']
            # token 过期时间 (秒)
            expires_in = result.get('expires_in', 2592000) 
            TOKEN_EXPIRATION_TIME = time.time() + expires_in
            print("Access Token 获取成功！")
            return ACCESS_TOKEN
        else:
            print(f"获取 Token 失败: {result}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"请求百度云 Token 失败: {e}")
        return None


def recognize_invoice(file_content: bytes, reimburser_name: str):
    """
    调用百度云增值税发票识别接口。
    
    Args:
        file_content: 发票文件的二进制内容。
        reimburser_name: 报销人姓名。
        
    Returns:
        tuple: (识别出的关键数据字典, 建议重命名的新文件名) 或 (None, None)
    """
    token = get_access_token()
    if not token:
        return None, None
        
    try:
        # 1. Base64 编码
        img_base64 = base64.b64encode(file_content).decode('utf-8')

        # 2. 构造请求
        request_url = f"{OCR_URL}?access_token={token}"
        params = {"image": img_base64}
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        
        # 3. 发送请求
        response = requests.post(request_url, data=params, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        
        if 'error_code' in result:
            print(f"OCR 识别 API 返回错误: {result.get('error_msg')}")
            return None, None

        # 4. 解析关键结果
        words_result = result.get('words_result', {})
        
        # 提取关键信息
        invoice_code = words_result.get('InvoiceCode', 'N/A')
        invoice_num = words_result.get('InvoiceNum', 'N/A')
        invoice_date_str = words_result.get('InvoiceDate', '').replace('年', '-').replace('月', '-').replace('日', '')
        # 总金额通常是 TotalAmount (不含税)，但为了确保金额准确，使用 AmountInFiguers (价税合计小写)
        total_figuers = words_result.get('AmountInFiguers')
        total_amount = float(words_result.get('TotalAmount', 0)) # 合计金额（不含税）
        total_tax = float(words_result.get('TotalTax', 0)) # 合计税额
        invoice_type = words_result.get('InvoiceType', '发票')
        
        # 提取交通类行程信息（使用第一个行程信息作为代表）
        if words_result.get('CommodityPlateNum'):
            # 这是一个交通发票（如：通行费电子普票）
            plate_num = words_result['CommodityPlateNum'][0]['word'] if words_result['CommodityPlateNum'] else 'N/A'
            start_date = words_result['CommodityStartDate'][0]['word'] if words_result['CommodityStartDate'] else 'N/A'
            end_date = words_result['CommodityEndDate'][0]['word'] if words_result['CommodityEndDate'] else 'N/A'
            
            # 使用行程信息丰富重命名
            rename_suffix = f"_{plate_num}"
            # 存储行程单信息，可以作为JSON格式存储到DB的Remarks字段
            trip_info = f"车牌号:{plate_num}, 起:{start_date}, 止:{end_date}"
        else:
            # 非交通发票
            rename_suffix = ""
            trip_info = words_result.get('Remarks', '') # 存储普通备注
        
        # 5. 智能重命名
        date_for_rename = invoice_date_str.replace('-', '')
        amount_for_rename = f"{total_figuers}" if total_figuers else f"{total_amount+total_tax:.2f}"
        
        # 格式：[日期]_[报销人]_[类型]_[金额]_[行程信息].pdf
        new_name = f"{date_for_rename}_{reimburser_name}_{invoice_type}_{amount_for_rename}{rename_suffix}.pdf"
        
        return {
            'invoice_code': invoice_code,
            'invoice_num': invoice_num,
            'invoice_date': invoice_date_str,
            'total_amount': total_amount, 
            'tax_amount': total_tax,
            'invoice_type': invoice_type,
            'remarks': trip_info # 存储行程单或备注
        }, new_name

    except requests.exceptions.RequestException as e:
        print(f"调用 OCR 识别接口失败: {e}")
        return None, None
    except Exception as e:
        print(f"处理 OCR 结果时发生错误: {e}")
        return None, None

# 初始化 Access Token，确保服务启动时鉴权一次

get_access_token()
