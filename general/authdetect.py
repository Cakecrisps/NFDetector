from typing import Optional, Tuple
import re


def is_auth_attempt(packet) -> Tuple[bool, Optional[str]]:
    """
    Определяет, содержит ли пакет признаки попытки аутентификации.
    
    Функция анализирует различные протоколы на предмет признаков 
    попыток входа в систему (аутентификации). Используется для 
    детекции brute-force атак по частоте попыток.
    
    Parameters
    ----------
    packet : pyshark.packet.packet.Packet
        Сетевой пакет для анализа
        
    Returns
    -------
    Tuple[bool, Optional[str]]
        - bool: True если обнаружена попытка аутентификации
        - str or None: Название протокола или None если не обнаружено
        
    Notes
    -----
    Поддерживаемые протоколы:
        - FTP: Команды USER/PASS
        - TELNET: Приглашения логина в тексте данных
        - SSH: Сообщения аутентификации (тип 21)
        - SMB/SMB2: Пакеты сессии и аутентификации
        
    Примеры использования
    ---------------------
    >>> if is_auth_attempt(packet)[0]:
    >>>     protocol = is_auth_attempt(packet)[1]
    >>>     print(f"Обнаружена аутентификация по протоколу {protocol}")
    """
    
    # FTP протокол - команды USER/PASS
    if hasattr(packet, 'ftp') and hasattr(packet.ftp, 'request_command'):
        if packet.ftp.request_command in ('USER', 'PASS'):
            return True, "FTP"
    
    # TELNET протокол - приглашения логина в тексте
    if hasattr(packet, 'telnet') and hasattr(packet.telnet, 'data'):
        telnet_data = packet.telnet.data
        # Проверка на шестнадцатеричное представление
        if ':' in telnet_data:
            try:
                # Преобразование hex строки в текст
                hex_str = telnet_data.replace(':', '')
                if len(hex_str) % 2 == 0:
                    byte_data = bytes.fromhex(hex_str)
                    text_data = byte_data.decode('utf-8', errors='ignore').lower()
                    
                    # Поиск приглашений ввода логина
                    login_patterns = ['login:', 'username:', 'user:']
                    for pattern in login_patterns:
                        if pattern in text_data:
                            return True, "TELNET"
            except (ValueError, UnicodeDecodeError):
                pass
    
    # SSH протокол - тип сообщения аутентификации
    if hasattr(packet, 'ssh') and hasattr(packet.ssh, 'message_type'):
        # SSH_MSG_USERAUTH_REQUEST = 50 (запрос аутентификации)
        # SSH_MSG_USERAUTH_PASSWD = 60 (аутентификация по паролю)
        if packet.ssh.message_type in ('21', '50', '60'):
            return True, "SSH"
    
    # SMB протокол (версия 1)   
    if hasattr(packet, 'smb'):
        # SMB Session Setup AndX Request (0x73)
        if (hasattr(packet.smb, 'cmd') and 
                packet.smb.cmd == '0x73' and 
                hasattr(packet.smb, 'flags_response') and
                packet.smb.flags_response == '0'):
            
            # Проверка наличия пользователя NTLM
            if hasattr(packet.smb, 'ntlmssp_auth_user'):
                user = packet.smb.ntlmssp_auth_user
                print(f"Попытка входа как {user}")
                return True, "SMB"
            
            # Дополнительные проверки для SMB
            if (hasattr(packet.smb, 'account_name') or
                    hasattr(packet.smb, 'security_blob')):
                return True, "SMB"
    
    # SMB2 протокол
    if hasattr(packet, 'smb2'):
        # SMB2 Session Setup Request (команда 1)
        if (hasattr(packet.smb2, 'cmd') and 
                packet.smb2.cmd == '1'):
            
            # Проверка различных полей аутентификации
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
        if packet.tcp.dstport == '3389':  # RDP порт
            # Проверка на наличие данных в пакете к RDP порту
            if (hasattr(packet, 'length') and 
                    int(packet.length) > 100):  # RDP пакеты обычно больше
                return True, "RDP"
    
    return False, None