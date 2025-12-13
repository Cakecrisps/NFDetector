#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль для определения попыток авторизации в сетевых пакетах.
"""

from typing import Optional, Tuple


def is_auth_attempt(packet) -> Tuple[bool, Optional[str]]:
    """
    Определяет, содержит ли пакет признаки попытки аутентификации.

    Анализирует различные сетевые протоколы на наличие признаков
    авторизации и аутентификации.

    Args:
        packet: Сетевой пакет для анализа (ожидается объект с полями протоколов).

    Returns:
        Tuple[bool, Optional[str]]: 
            - bool: True если обнаружена попытка аутентификации
            - str или None: Тип протокола или None если попытка не обнаружена

    Протоколы, которые определяются:
        - FTP (команды USER/PASS)
        - TELNET (признаки login/password)
        - SSH (сообщения аутентификации)
        - SMB/SMB2 (NTLMSSP и команды Session Setup)
        - RDP (порт 3389 и специфические данные)
        - HTTP Basic Auth (заголовки Authorization)
    """
    try:
        if hasattr(packet, 'ftp') and hasattr(packet.ftp, 'request_command'):
            cmd = str(packet.ftp.request_command).upper()
            if cmd in ('USER', 'PASS'):
                return True, "FTP"

        if hasattr(packet, 'telnet') and hasattr(packet.telnet, 'data'):
            telnet_data = str(packet.telnet.data)
            if ':' in telnet_data:
                try:
                    hex_str = telnet_data.replace(':', '')
                    if len(hex_str) % 2 == 0:
                        byte_data = bytes.fromhex(hex_str)
                        text_data = byte_data.decode('utf-8', 
                                                    errors='ignore').lower()
                        login_patterns = ['login:', 'username:', 
                                         'user:', 'password:']
                        for pattern in login_patterns:
                            if pattern in text_data:
                                return True, "TELNET"
                except (ValueError, UnicodeDecodeError):
                    pass

        if hasattr(packet, 'ssh') and hasattr(packet.ssh, 'message_type'):
            msg_type = str(packet.ssh.message_type).strip()
            if msg_type in ('21', '50', '51', '60'):
                return True, "SSH"

        # КРИТИЧЕСКОЕ: Проверка SMB v1
        if hasattr(packet, 'smb'):
            if hasattr(packet.smb, 'cmd'):
                cmd_value = str(packet.smb.cmd).strip()
                
                if cmd_value.startswith('0x'):
                    cmd_num = int(cmd_value, 16)
                else:
                    try:
                        cmd_num = int(cmd_value)
                    except ValueError:
                        cmd_num = -1
                
                if cmd_num == 0x73 or cmd_num == 115:
                    if hasattr(packet.smb, 'security_blob'):
                        sec_blob = str(packet.smb.security_blob).upper()
                        if 'NTLMSSP' in sec_blob:
                            return True, "SMB"
                    
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
                            if value and value not in ('0', '00', '000', 
                                                      'N/A', 'NULL'):
                                return True, "SMB"
                    
                    if (hasattr(packet.smb, 'v2_domain') or 
                        hasattr(packet.smb, 'v2_account')):
                        return True, "SMB"
            
            for attr in dir(packet.smb):
                if not attr.startswith('_'):
                    try:
                        value = str(getattr(packet.smb, attr))
                        if 'NTLMSSP' in value.upper():
                            return True, "SMB"
                        if any(x in value.lower() for x in 
                               ['auth', 'user', 'account', 'domain', 'login']):
                            if len(value) > 2:
                                return True, "SMB"
                    except (AttributeError, TypeError):
                        continue

        # КРИТИЧЕСКОЕ: Проверка SMB2
        if hasattr(packet, 'smb2'):
            if hasattr(packet.smb2, 'cmd'):
                cmd_value = str(packet.smb2.cmd).strip()
                
                if cmd_value.startswith('0x'):
                    cmd_num = int(cmd_value, 16)
                else:
                    try:
                        cmd_num = int(cmd_value)
                    except ValueError:
                        cmd_num = -1
                
                if cmd_num == 1 or cmd_num == 0x01:
                    if hasattr(packet.smb2, 'security_blob'):
                        sec_blob = str(packet.smb2.security_blob).upper()
                        if 'NTLMSSP' in sec_blob:
                            return True, "SMB2"
                    
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
                            if value and value not in ('0', '00', '000', 
                                                      'N/A', 'NULL'):
                                return True, "SMB2"

        if hasattr(packet, 'tcp'):
            dst_port = str(packet.tcp.dstport)
            src_port = str(packet.tcp.srcport)
            
            if dst_port == '3389' or src_port == '3389':
                if hasattr(packet, 'tpkt'):
                    return True, "RDP"
                elif hasattr(packet, 'data') and packet.data:
                    data_str = str(packet.data).upper()
                    if 'RDP' in data_str or 'CREDSSP' in data_str:
                        return True, "RDP"

        if hasattr(packet, 'http'):
            if hasattr(packet.http, 'authorization'):
                auth_header = str(packet.http.authorization).lower()
                if 'basic' in auth_header:
                    return True, "HTTP Basic"
            elif hasattr(packet.http, 'request'):
                request = str(packet.http.request).lower()
                if 'authorization:' in request or 'www-authenticate:' in request:
                    return True, "HTTP Auth"
        
        return False, None
        
    except Exception:
        return False, None
