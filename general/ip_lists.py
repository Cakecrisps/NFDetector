"""Shared parsing of IP lists with full-line and inline comments."""


def load_ip_list(lines):
    return {
        address
        for line in lines
        if (address := line.split('#', 1)[0].strip())
    }
