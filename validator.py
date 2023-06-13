import ipaddress


class Validator:
    @staticmethod
    def is_validate_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def get_version_ip(ip):
        return ipaddress.ip_address(ip).version

    @staticmethod
    def is_validate_protocol(protocol):
        return protocol.lower() in ('tcp', 'udp', 'icmp')

    @staticmethod
    def is_validate_options_for_protocol(args):
        return not (args.Protocol in ('tcp', 'udp') and not args.p)

    @staticmethod
    def is_validate_input(args):
        if not Validator.is_validate_protocol(args.Protocol):
            print('Неправильно выбран протокол. Поддерживаются следующие протоколы: tcp, udp, icmp')
            return False

        if not Validator.is_validate_options_for_protocol(args):
            print('Для указаного протокола требуется узакать порт (опция -p)')
            return False

        if not Validator.is_validate_ip(args.IP):
            print('Неправильный формат IP адреса')
            return False

        return True

