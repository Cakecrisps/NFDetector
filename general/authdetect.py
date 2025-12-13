#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Модуль для определение авторизаций.

"""
from typing import Optional, Tuple

def is_auth_attempt(packet) -> Tuple[bool, Optional[str]]:
    """
    Определяет, содержит ли пакет признаки попытки аутентификации.
    """
    try:
        # FTP протокол - команды USER/PASS
        if hasattr(packet, 'ftp') and hasattr(packet.ftp, 'request_command'):
            cmd = str(packet.ftp.request_command).upper()
            if cmd in ('USER', 'PASS'):
                return True, "FTP"
        
        # TELNET протокол
        if hasattr(packet, 'telnet') and hasattr(packet.telnet, 'data'):
            telnet_data = str(packet.telnet.data)
            if ':' in telnet_data:
                try:
                    hex_str = telnet_data.replace(':', '')
                    if len(hex_str) % 2 == 0:
                        byte_data = bytes.fromhex(hex_str)
                        text_data = byte_data.decode('utf-8', errors='ignore').lower()
                        login_patterns = ['login:', 'username:', 'user:', 'password:']
                        for pattern in login_patterns:
                            if pattern in text_data:
                                return True, "TELNET"
                except (ValueError, UnicodeDecodeError):
                    pass
        
        # SSH протокол
        if hasattr(packet, 'ssh') and hasattr(packet.ssh, 'message_type'):
            # 21 - SSH_MSG_USERAUTH_REQUEST, 50-51 - SSH_MSG_USERAUTH
            msg_type = str(packet.ssh.message_type).strip()
            if msg_type in ('21', '50', '51', '60'):
                return True, "SSH"
        
        # SMB v1 протокол - КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ
        if hasattr(packet, 'smb'):
            # ДЕБАГ: Выводим все атрибуты SMB для анализа
            
            
            # Вариант 1: Проверка по команде Session Setup AndX (0x73)
            if hasattr(packet.smb, 'cmd'):
                cmd_value = str(packet.smb.cmd).strip()
                
                # Обрабатываем разные форматы команды
                if cmd_value.startswith('0x'):
                    cmd_num = int(cmd_value, 16)
                else:
                    try:
                        cmd_num = int(cmd_value)
                    except:
                        cmd_num = -1
                
                # Session Setup AndX Request = 0x73 = 115
                if cmd_num == 0x73 or cmd_num == 115:
                    # Проверяем различные признаки аутентификации
                    
                    # 1. Проверка наличия NTLMSSP в security_blob
                    if hasattr(packet.smb, 'security_blob'):
                        sec_blob = str(packet.smb.security_blob).upper()
                        if 'NTLMSSP' in sec_blob:
                            return True, "SMB"
                    
                    # 2. Проверка наличия данных аутентификации в других полях
                    auth_attrs = [
                        'ntlmssp_auth_user',
                        'ntlmssp_account_name', 
                        'ntlmssp_domain_name',
                        'account_name',
                        'primary_domain',
                        'user',
                        'auth_user',
                        'native_os',
                        'native_lanman'
                    ]
                    
                    for attr in auth_attrs:
                        if hasattr(packet.smb, attr):
                            value = str(getattr(packet.smb, attr)).strip()
                            if value and value not in ('0', '00', '000', 'N/A', 'NULL'):
                                return True, "SMB"
                    
                    # 3. Проверка по наличию данных в v2_domain или v2_account
                    if hasattr(packet.smb, 'v2_domain') or hasattr(packet.smb, 'v2_account'):
                        return True, "SMB"
            
            # Вариант 2: Проверка по другим признакам SMB
            # Ищем любые признаки NTLMSSP или аутентификации
            for attr in dir(packet.smb):
                if not attr.startswith('_'):
                    try:
                        value = str(getattr(packet.smb, attr))
                        if 'NTLMSSP' in value.upper():
                            return True, "SMB"
                        if any(x in value.lower() for x in ['auth', 'user', 'account', 'domain', 'login']):
                            if len(value) > 2:  # Чтобы не ловить "0"
                                return True, "SMB"
                    except:
                        continue
        
        # SMB2 протокол - КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ
        if hasattr(packet, 'smb2'):
            # ДЕБАГ: Выводим все атрибуты SMB2 для анализа
            # print("\n=== SMB2 Packet Attributes ===")
            # for attr in dir(packet.smb2):
            #     if not attr.startswith('_'):
            #         try:
            #             value = getattr(packet.smb2, attr)
            #             if value and str(value).strip() not in ('0', '00', '000', ''):
            #                 print(f"{attr}: {value}")
            #         except:
            #             pass
            
            # SMB2 Session Setup Command = 1 (0x01)
            if hasattr(packet.smb2, 'cmd'):
                cmd_value = str(packet.smb2.cmd).strip()
                
                # Обрабатываем разные форматы
                if cmd_value.startswith('0x'):
                    cmd_num = int(cmd_value, 16)
                else:
                    try:
                        cmd_num = int(cmd_value)
                    except:
                        cmd_num = -1
                
                if cmd_num == 1 or cmd_num == 0x01:
                    # Проверяем признаки аутентификации
                    
                    # 1. Проверка security_blob на NTLMSSP
                    if hasattr(packet.smb2, 'security_blob'):
                        sec_blob = str(packet.smb2.security_blob).upper()
                        if 'NTLMSSP' in sec_blob:
                            return True, "SMB2"
                    
                    # 2. Проверка других полей
                    smb2_auth_fields = [
                        'ntlmssp_auth_user',
                        'ntlmssp_account_name',
                        'ntlmssp_domain_name',
                        'ntlmssp_nt_response',
                        'ntlmssp_lm_response',
                        'user_name',
                        'domain_name',
                        'account_name',
                        'session_key',
                        'auth_user'
                    ]
                    
                    for field in smb2_auth_fields:
                        if hasattr(packet.smb2, field):
                            value = str(getattr(packet.smb2, field)).strip()
                            if value and value not in ('0', '00', '000', 'N/A', 'NULL'):
                                return True, "SMB2"
        
        # RDP протокол
        if hasattr(packet, 'tcp'):
            dst_port = str(packet.tcp.dstport)
            src_port = str(packet.tcp.srcport)
            
            if dst_port == '3389' or src_port == '3389':
                # Проверяем TPKT (RDP поверх TPKT)
                if hasattr(packet, 'tpkt'):
                    return True, "RDP"
                # Проверяем по данным
                elif hasattr(packet, 'data') and packet.data:
                    data_str = str(packet.data).upper()
                    if 'RDP' in data_str or 'CREDSSP' in data_str:
                        return True, "RDP"
        
        # HTTP Basic Auth
        if hasattr(packet, 'http'):
            # Проверка заголовка Authorization
            if hasattr(packet.http, 'authorization'):
                auth_header = str(packet.http.authorization).lower()
                if 'basic' in auth_header:
                    return True, "HTTP Basic"
            # Проверка в запросе
            elif hasattr(packet.http, 'request'):
                request = str(packet.http.request).lower()
                if 'authorization:' in request or 'www-authenticate:' in request:
                    return True, "HTTP Auth"
        
        return False, None
        
    except Exception as e:
        # Тихая обработка ошибок
        # print(f"Ошибка при анализе пакета: {e}")
        return False, None