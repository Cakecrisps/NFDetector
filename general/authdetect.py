#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional, Tuple
import re


def is_auth_attempt(packet) -> Tuple[bool, Optional[str]]:
    """
    Определяет, содержит ли пакет признаки попытки аутентификации.
    
    Args:
        packet: Сетевой пакет для анализа
        
    Returns:
        Tuple[bool, Optional[str]]: 
            - bool: True если обнаружена попытка аутентификации
            - str or None: Название протокола или None если не обнаружено
    """
    
    try:
        # FTP протокол - команды USER/PASS
        if hasattr(packet, 'ftp') and hasattr(packet.ftp, 'request_command'):
            if packet.ftp.request_command in ('USER', 'PASS'):
                return True, "FTP"
        
        # TELNET протокол - приглашения логина в тексте
        if hasattr(packet, 'telnet') and hasattr(packet.telnet, 'data'):
            telnet_data = packet.telnet.data
            if ':' in telnet_data:
                try:
                    hex_str = telnet_data.replace(':', '')
                    if len(hex_str) % 2 == 0:
                        byte_data = bytes.fromhex(hex_str)
                        text_data = byte_data.decode('utf-8', errors='ignore').lower()
                        login_patterns = ['login:', 'username:', 'user:']
                        for pattern in login_patterns:
                            if pattern in text_data:
                                return True, "TELNET"
                except (ValueError, UnicodeDecodeError):
                    pass
        
        # SSH протокол - тип сообщения аутентификации
        if hasattr(packet, 'ssh') and hasattr(packet.ssh, 'message_type'):
            if packet.ssh.message_type in ('21', '50', '60'):
                return True, "SSH"
        
        # SMB протокол (версия 1)   
        if hasattr(packet, 'smb'):
            if (hasattr(packet.smb, 'cmd') and 
                    packet.smb.cmd == '0x73' and 
                    hasattr(packet.smb, 'flags_response') and
                    packet.smb.flags_response == '0'):
                
                if hasattr(packet.smb, 'ntlmssp_auth_user'):
                    user = packet.smb.ntlmssp_auth_user
                    return True, "SMB"
                
                if (hasattr(packet.smb, 'account_name') or
                        hasattr(packet.smb, 'security_blob')):
                    return True, "SMB"
        
        # SMB2 протокол
        if hasattr(packet, 'smb2'):
            if (hasattr(packet.smb2, 'cmd') and 
                    packet.smb2.cmd == '1'):
                
                auth_fields = [
                    'ntlmssp_auth_user',
                    'security_blob',
                    'user',
                    'account_name',
                    'ntlmssp_nt_response',
                    'ntlmssp_lm_response'
                ]
                
                for field in auth_fields:
                    if hasattr(packet.smb2, field):
                        return True, "SMB2"
        
        # RDP протокол (базовая проверка)
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport'):
            if packet.tcp.dstport == '3389':
                if (hasattr(packet, 'length') and 
                        int(packet.length) > 100):
                    return True, "RDP"
        
        return False, None
        
    except AttributeError:
        return False, None
    except Exception as e:
        print(f"Ошибка при анализе пакета: {e}")
        return False, None